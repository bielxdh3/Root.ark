# Root.ark Dual Recovery Revision 3 Bounded Foundation Plan

> For agentic workers: REQUIRED SUB-SKILL: use superpowers:executing-plans after the user accepts this plan. Track steps with checkboxes. No product-code work before plan approval. Direct Codex is the default; native subagents are allowed only when runtime metadata proves their identity, model, effort, and repository binding. Do not use Dual Agents or Dual Codex.

**Goal:** Complete only the bounded Node crypto-library foundation for the already approved dual-recovery design, while keeping server integration, device-specific storage, deployment, and product recovery blocked until their prerequisites are verified.

**Architecture:** Reuse Root.ark's existing rootark-zk-1 deterministic CBOR, HPKE, AES-GCM, Ed25519, and keyring primitives. Keep recovery package/KDF, manifest/history verification, and a clearly mock-only CAS/witness state model in separate existing modules. Do not create a server or client adapter in this plan.

**Tech Stack:** CommonJS, Node.js 22, built-in node:test, the current lockfile's cborg, HPKE packages, and libsodium wrappers. The Argon2id profile remains provisional. No dependency or lockfile change is planned.

**Spec:** docs/superpowers/specs/2026-10-19-rootark-dual-recovery-design.md as reviewed at commit b5b31b31e407df02cdc023d46d841714e2bc5622, parent d1af0424678f85b27a1cf811dc2c0e94cce6713a. Review verdict: ARCHITECTURE_ACCEPTED_FOR_BOUNDED_EXECUTION_PLANNING. The review is not runtime, deployment, production, or issue #65 acceptance.

## Global Constraints

- The owner-approved recovery policy is both a user-held emergency package and previously trusted devices. No server/admin master key, hidden fallback, or default delegate.
- Preserve the rootark-zk-1 suite, deterministic CBOR, RFC 9180 HPKE X25519/HKDF-SHA256/AES-256-GCM, AES-256-GCM package encryption, Ed25519 authorization, exact scope binding, and existing v1 keyring shape.
- Keep the package KDF candidate exactly Argon2id v1.3, 16-byte random salt, 32-byte output, opslimit 3, and memlimit 268435456 bytes. It is not runtime-approved. No profile downgrade, attacker-selected cost, synchronous main-thread call, or fallback.
- Use one worker per active derivation, one active derivation per process, no queue, and KDF_BUSY for contention. Worker error, timeout, allocation failure, or unsupported platform fails closed.
- Enforce the reviewed 8 MiB package envelope cap, 7 MiB decrypted payload cap, exact deterministic-CBOR field sets, parse-before-KDF, and the exact KDF tuple.
- Never mutate v1 rootKey. A new v2 recovery API may omit it only after a bounded in-repository and external-consumer inventory; v2 rejects an unexpected rootKey and never converts a v1 object.
- Enforce 256-device and 64-epoch manifest bounds; 4096 history transitions; 8 MiB per history entry; 64 MiB total history; and 8 MiB per returned page. Warn at 75 percent. Never prune, truncate, or checkpoint history in this plan.
- History and state-model tests do not prove a fresh head, CAS, witness, durable high-water mark, server admission, or deployment guarantee.
- A compromised-package transition requires an active trusted device and all required old epoch keys. It atomically revokes the old package authority, creates one fresh independent epoch, and wraps that epoch only to remaining active devices and the replacement package. Missing authority or keys fails closed; old copies remain compromised.
- A pending witness reservation blocks new state-dependent authorization and server-mediated read/write admission. Offline-held keys, plaintext, and ciphertext cannot be remotely revoked; offline uploads remain unaccepted drafts until fresh reconciliation.
- No routes, persistence adapters, shared CAS, CAS-status authority, witness deployment, content gate, OS keychain, client high-water provider, browser/mobile workflow, retention/export/pairing UX, migration, or production behavior is implemented here.
- Use the existing isolated E: worktree. Preserve the current dirty files and primary checkout. Do not push, create or update a PR, merge, deploy, change issue state, or close issue #65. Any later local commit must contain exactly one Co-authored-by: Codex <codex@openai.com> line.
- Query AI Memory through MCP again immediately before execution. Apply Ponytail in full and the applicable Superpowers planning/execution/testing/review workflows. UI-UX-PRO-MAX was read; no interface is in scope, so do not apply UI rules or invent a flow. Load it for any separately approved UI phase. Do not use Obsidian.

## Current State and Capability Evidence

This snapshot was checked while preparing this plan on 2026-10-19:

- Canonical repository: E:\servidor. Active worktree: E:\servidor\.worktrees\zk-dual-recovery-20261019. Branch: cdx/rootark-dual-recovery-20261019. HEAD: 029ff28cef298164f1432ee08752beadcc6d5783, parent 39748936a9624624fa0ee909980e5f7bb2c05ef3.
- The active worktree has eight tracked modified files: the spec; recovery history, manifest, and package source modules; history, manifest, and package tests; and the shared recovery test fixtures. These are carryover changes. Do not overwrite, reset, stage, commit, or call them accepted. Review their exact diff before any post-approval execution.
- The local origin/Root/main tracking ref is 0636d638eee1ca5a75fde59936a9dbd3c66077cd and is stale. GitHub reported current Root/main as fe8364bd506f01b5bf6c092e82788e10cfd05b42. PR #224 is merged; issue #65 remains open. Reconcile branch ancestry after plan approval without rewriting shared history or disturbing the dirty worktree.
- The reviewed architecture commit b5b31b31e407df02cdc023d46d841714e2bc5622 is an ancestor of the active HEAD. The on-disk spec has an uncommitted delta, so the reviewed commit, not the working file, is the current approved design input.
- The existing plan docs/superpowers/plans/2026-10-19-rootark-dual-recovery.md is preserved. This revision-specific plan is separate and does not replace that file until the user accepts it.
- GitHub issue #65 remains open. The owner comment 6260021696 approves both recovery methods and forbids administrator recovery; PR #224 records that decision and is merged.

Repository capability evidence:

- db/index.js uses better-sqlite3 at data/rootark.sqlite by default; DB_ENABLED defaults to false. It is local SQLite, not a shared CAS implementation.
- server.js rejects multiple server instances while authentication state is process-local. src/routes/sync.js defaults opaque sync objects to a local JSON file and keeps some authorization/rate state in process memory. The scoped source inventory found no shared-CAS adapter.
- public/client/rootark-protected-store.js encrypts values for IndexedDB using a raw key supplied by the caller. IndexedDB does not protect that key or provide a rollback-resistant high-water mark.
- sync-client/rootark-sync-v2.js loads ROOTARK_SYNC_FILE_KEY and device private-key material from environment variables into process memory. That is not OS-backed device key storage.
- No shared CAS, independently pinned CAS-status authority, witness service/key bootstrap, OS-backed keychain, or rollback-resistant client storage was selected or verified. Do not silently substitute SQLite, JSON, environment variables, or IndexedDB.

AI Memory preflight for this planning turn used a project-scoped query for Root.ark #65 dual recovery, CAS, trusted devices, key storage, and blocked integrations. It returned the current Root.ark recovery session summary and a global development-prompt preference; no maintained project decision was found that supersedes the supplied review or current source. Do not treat the session log as authority. No subagent was used.

## Review Report and Security Decision Record

The supplied independent review examined revision-3 spec commit b5b31b31e407df02cdc023d46d841714e2bc5622, parent d1af0424678f85b27a1cf811dc2c0e94cce6713a. It reports a clean single-file spec diff and git diff --check success at that reviewed commit. It performed no implementation or runtime tests and explicitly is not formal cryptographic certification.

The review accepts the architecture for bounded execution planning only:

- Pending reservation safety is addressed in design: a durable pending gate precedes tickets; unresolved reservations block fresh security-sensitive reads and writes; an old committed head is unacceptable; reconciliation needs a separately pinned truthful linearizable CAS-status authority; ambiguous state stays blocked.
- Compromised-package response is addressed in design: only an active trusted device can initiate it; replacement package, revocation, and one-step fresh epoch rotation share the signed CAS transition; the old package never receives the new epoch. Missing keys or the last usable authority fails closed.
- Signed contiguous history, prior-state actor authorization, live target challenge verification, non-circular package activation, exact package-byte binding, and conditional rootKey omission remain required and are not runtime evidence.

| Review question | Accepted design decision | Required qualification |
|---|---|---|
| Pending gate and offline access | Acceptable for new server-mediated admissions and state-dependent operations. | Cached plaintext and already-held keys cannot be remotely revoked. Offline writes remain drafts. Resolve any existing promise of fresh state-dependent offline access before runtime admission work. |
| CAS-status authority | Acceptable only as a target trust assumption. | Independently pin its key; prove truthful linearizable terminal results, durable ledger, restart/restore, and irreversible final no-commit tombstones. An app-server assertion or mock is insufficient. |
| Package compromise | Mandatory active-device replacement and forward rotation are accepted. | Require every historical epoch key, verified export and approved retention confirmation, fresh recovery signer/wrap key, new epoch, and one atomic CAS transition. No voluntary device-only downgrade is approved. Previously copied old keys remain usable. |
| Operation lifetime | 300-second nominal lifetime with 30-second monitored clock skew is accepted as 330 seconds maximum effective lifetime. | No post-expiry grace. CAS and witness monitor clock health; operation IDs/reservations remain single-use. Test all boundaries. |
| History limits | Prototype bounds of 4096 transitions, 64 MiB total, and 75 percent warning are accepted for bounded work. | Hard exhaustion can block revocation and compromise response. No production readiness until separately reviewed checkpoint/rekey or capacity lifecycle. Test 256-device/64-epoch serialized sizes. |
| KDF and rootKey | Conditional acceptance only. | Validate fixed Argon2id13 vectors, Node 22 Windows/Linux runtime, minimum-hardware time/RSS, worker allocation/error behavior, and parsing before allocation. Preserve v1 rootKey and block omission if any real consumer is found. |

The following exact wire detail remains a pre-code gate. The reviewed b5 spec defines the base receipt field list but does not assign its exact type string or signing domain; it does define a separate fresh-head type/domain and schema. The current uncommitted spec delta is not covered by the b5 review. Before implementing either receipt parser, obtain an independently reviewed normative amendment naming the distinct base receipt type and domain. Tests must reject a fresh-head receipt or pending response in the committed base slot. Do not infer these values from the dirty test fixture or module implementation.

## Review Focus

1. Malformed, duplicate, noncanonical, oversized, wrong-scope, or unsupported-profile packages fail before KDF allocation and return no plaintext. Tests: issue-65-recovery-package.test.js and issue-65-recovery-kdf.test.js.
2. Wrong password, altered AAD/ciphertext/tag, wrong account/compartment, substituted package bytes, or incomplete epoch coverage fail closed. Tests: issue-65-recovery-package.test.js and issue-65-recovery-rootkey-compat.test.js.
3. Public transition verification succeeds using only public state and never consumes epoch secrets; client MAC and key-possession checks still fail without required local keys. Tests: issue-65-recovery-manifest-v2.test.js.
4. Signed synthetic, tampered, missing, reordered, wrong-recipient, or unopenable recovery wraps never yield complete recoverability. Tests: issue-65-recovery-history-v2.test.js with real HPKE fixture keys/ciphertexts.
5. Unresolved reservations, stale app-store restore, outage/restart, idempotency conflict, concurrent writes, missing final authority, compromise rotation, and capacity exhaustion preserve fail-closed state. Tests: issue-65-recovery-state-model.test.js, issue-65-recovery-package-compromise.test.js, and issue-65-recovery-history-capacity.test.js. Mock-only results never close provider gates.

## Repository-Grounded File Map

| Path | Responsibility |
|---|---|
| src/crypto/rootark-zk-1.js | Reuse existing deterministic CBOR, HPKE, AES-GCM, crypto errors, and secret clearing. No planned edits. |
| src/crypto/rootark-zk-keyring.js | Preserve v1 keyring/rootKey behavior. No planned edits. |
| src/crypto/rootark-zk-recovery-kdf.js and src/crypto/rootark-zk-recovery-kdf-worker.js | Fixed-profile input checks, one-worker gate, timeout/error mapping, and worker implementation. |
| src/crypto/rootark-zk-recovery-package-v1.js | Exact package envelope, parse-before-KDF, activation/AAD digest binding, payload checks, and package round trip. |
| src/crypto/rootark-zk-recovery-manifest-v2.js | Public transition verifier, actor matrix, signature/MAC split, revision and compromise invariants. |
| src/crypto/rootark-zk-recovery-authorization.js | Target challenge and Ed25519 response validation; no claim that the server proves X25519 private-key possession from public bytes alone. |
| src/crypto/rootark-zk-recovery-history-v2.js | Contiguous chain, capacity checks, client-side key coverage, and HPKE opening of newly added recovery wraps. |
| test/support/issue-65-recovery-v2-fixtures.js | Runtime-generated real keypairs, valid HPKE wraps, and deterministic protocol fixtures. No fixed secrets. |
| test/issue-65-recovery-kdf.test.js | Fixed tuple, one worker/no queue, errors, parsing-before-worker, and KDF vector hook. |
| test/issue-65-recovery-package.test.js and test/issue-65-recovery-rootkey-compat.test.js | Package format, tamper/scope, witness schema, v1 compatibility, and no implicit rootKey conversion. |
| test/issue-65-recovery-manifest-v2.test.js and test/issue-65-recovery-authorization.test.js | Public-only verification, client key proof, actor matrix, clock limits, and target proof boundary. |
| test/issue-65-recovery-history-v2.test.js and test/issue-65-recovery-package-compromise.test.js | Wrap opening, history continuity, compromise rotation, last-authority failure, and stale identifier rejection. |
| test/issue-65-recovery-history-capacity.test.js | Exact serialized capacity boundaries, warnings, and no-truncation behavior. |
| test/support/issue-65-recovery-state-model.js and test/issue-65-recovery-state-model.test.js | Test-only CAS/witness/admission simulation; never imported by product runtime. |

Ownership: one direct Codex implementer for the sequential crypto phases; a separate read-only reviewer after an exact final SHA is available. Do not delegate unless trustworthy native runtime metadata proves the requested agent settings and the work can be separated without sharing file edits.

---

## Phase 0 - Plan Approval, Carryover Reconciliation, and Wire-Format Gate

**Owner:** Coordinator. **Deliverable:** approved plan, preserved worktree, and no unresolved wire-format value entering code.

- [ ] Step 1: Obtain user approval of this plan. Do not begin product-code changes before it.
- [ ] Step 2: Re-read current AI Memory for this repository and task. Verify actual current worktree HEAD/status and the exact remote Root/main ref. Do not rely on the snapshot above if it changed.
- [ ] Step 3: Review, do not overwrite, all eight tracked carryover diffs listed above. Classify each hunk against Phases 1-3. Keep unrelated or unknown hunks untouched. If a safe clean execution tree is needed, create it only under E:\servidor\.worktrees and preserve this original checkout.
- [ ] Step 4: Add a narrowly scoped normative spec amendment for the base witness receipt's exact type and signing domain, distinct from the fresh-head type/domain. Obtain independent security review of that amendment before implementing the corresponding parser. If the amendment is rejected or not reviewed, keep package-base receipt verification blocked.
- [ ] Step 5: Re-run the bounded rootKey call-site/serialization inventory. Keep v1 behavior unchanged; if any external or in-repo consumer requires rootKey in recovery, stop that format slice for separate review.
- [ ] Step 6: Record infrastructure as blocked: no selected shared CAS, no separately pinned status authority, no deployed witness, no supported OS keychain/high-water provider. Do not turn this into a task to choose or provision one.

Expected phase outcome: a stable execution base and clear spec source. No source-code change is authorized by this plan until Step 1 passes; the wire-format-dependent code remains gated on Step 4.

## Phase 1 - Recovery Package and Bounded KDF Library

**Owner:** Crypto implementer. **Deliverable:** client-side package create/open/activation primitives with fixed, bounded KDF execution; no server endpoint.

**Interfaces:** preserve exports deriveRecoveryKeyBounded(input), parseRecoveryPackageV1(input), createRecoveryPackageV1(input), openRecoveryPackageV1(input), recoveryPackageEnvelopeDigest(input), and verifyRecoveryPackageActivation(input). The KDF input uses password bytes and a 16-byte salt; package creation/opening use the reviewed exact envelope and payload fields. Keep all secrets in caller memory and best-effort clear temporary buffers.

**Files:** src/crypto/rootark-zk-recovery-kdf.js; src/crypto/rootark-zk-recovery-kdf-worker.js; src/crypto/rootark-zk-recovery-package-v1.js; test/issue-65-recovery-kdf.test.js; test/issue-65-recovery-package.test.js; test/issue-65-recovery-rootkey-compat.test.js; test/support/issue-65-recovery-v2-fixtures.js.

- [ ] Step 1: Add/retain a failing independent-vector test for Argon2id v1.3 using the exact tuple: 16-byte salt, 32-byte output, opslimit 3, memlimit 268435456 bytes. Expected: the pinned runtime result matches an independently generated reference vector.
- [ ] Step 2: Prove RED for malformed salt, password length, KDF tuple, envelope field set, size cap, noncanonical CBOR, wrong scope, and base receipt schema. Assert the worker/KDF has not started for all parse/profile failures.
- [ ] Step 3: Prove RED for KDF_BUSY, worker startup/error/exit/timeout/allocation failure. Expected errors: KDF_BUSY for a concurrent call and RECOVERY_KDF_FAILED for worker failure; no fallback tuple and no main-thread KDF.
- [ ] Step 4: Implement the minimum fixes in the existing KDF/package modules using only the exact fixed profile and reviewed deterministic-CBOR/AES-GCM domains.
- [ ] Step 5: Replace any fake positive recovery material with runtime-generated keys and authenticated values. Preserve a wrong-password, tamper, scope-substitution, one-byte envelope-substitution, and incomplete-key-coverage negative case.
- [ ] Step 6: Prove RED/GREEN for v1 compatibility. The v1 keyring retains its existing rootKey and serialized shape; the v2 parser rejects v1 input and unexpected rootKey without mutating or silently converting either object.
- [ ] Step 7: Run node --test test/issue-65-recovery-kdf.test.js test/issue-65-recovery-package.test.js test/issue-65-recovery-rootkey-compat.test.js. Expected: focused package tests pass on the supported runtime; this does not approve KDF production use or prove user retention.
- [ ] Step 8: Capture, but do not freeze, Node 22 Windows/Linux vector, elapsed time, peak RSS, worker failure, and minimum-hardware evidence. If a supported environment or independent reference is unavailable, report KDF_PROFILE_VALIDATION_BLOCKED and keep the profile provisional.
- [ ] Step 9: Commit only the completed Phase 1 files after diff review and exact tests; do not push.

## Phase 2 - Public Authorization, Client History, and Recovery Wrap Proof

**Owner:** Crypto implementer. **Deliverable:** public transition checks separated from client-only possession, plus recoverability proven by opening real HPKE wraps.

**Interfaces:** preserve verifyRecoveryTransitionPublicV2(input), verifyRecoveryTransitionMacV2(input), signRecoveryTransitionV2(input), verifyRecoveryHistoryV2(input), and the target-pop exports. Public verification receives no private epoch keys, recovery private key, or MAC key. Client history verification may receive recoveryPackageKeys records with package_id, hpke_key_id, and hpke_private_key; these never enter the public verifier.

**Files:** src/crypto/rootark-zk-recovery-manifest-v2.js; src/crypto/rootark-zk-recovery-history-v2.js; src/crypto/rootark-zk-recovery-authorization.js; src/crypto/rootark-zk-recovery-package-v1.js only where activation binding is incomplete; test/issue-65-recovery-manifest-v2.test.js; test/issue-65-recovery-history-v2.test.js; test/issue-65-recovery-authorization.test.js; test/issue-65-recovery-package-compromise.test.js; test/issue-65-recovery-history-capacity.test.js; test/support/issue-65-recovery-v2-fixtures.js.

- [ ] Step 1: Prove RED for public verification of a valid revoke-device transition with public inputs only. It must pass signature/state/revision checks without private epoch keys. Prove unauthorized actor and secret-bearing input rejection. Then prove the separate client MAC/key-coverage check fails with absent or wrong local epoch keys using KEY_COVERAGE_INCOMPLETE.
- [ ] Step 2: Prove RED for a signed recovery wrap that has a random encapsulated key/ciphertext, a modified encapsulated key, wrong recipient/key ID, wrong epoch/key_ref, or no recovery private key. History must not return complete=true. Expected client error: KEY_COVERAGE_INCOMPLETE.
- [ ] Step 3: Add runtime-generated HPKE X25519 keypairs and real ciphertext to test/support/issue-65-recovery-v2-fixtures.js. Positive fixtures must open with the exact trusted scope, info, and AAD and match the authenticated epoch key. Add a test where every newly added required recovery wrap opens.
- [ ] Step 4: Implement client-only opening of every newly added recovery wrap after public signature and manifest checks. Use trusted expected account, compartment, keyring, package, epoch, key_ref, and wrap ID context. Compare each opened 32-byte key with the locally authenticated epoch key and clear temporary buffers. Do not pass secrets to the public verifier.
- [ ] Step 5: Prove RED/GREEN for register-package, replace-package, revoke-device, and compromise-package additions. A missing/invalid wrap blocks the whole result; partial recovery is not defined.
- [ ] Step 6: Prove RED/GREEN for compromise-package. A current active device, complete prior epoch keys, a new independent recovery signing/wrapping authority, exact +1 epoch rotation, and complete wraps are required in one signed transition. The new epoch wrap set excludes the compromised package. Missing historical keys or no usable active device fail with COMPROMISE_RECOVERY_UNAVAILABLE or KEY_COVERAGE_INCOMPLETE before commit.
- [ ] Step 7: Prove the target-proof boundary. The authorizer verifies the unpredictable challenge returned over the authenticated pairing interaction and the Ed25519 signature. A public transcript alone never claims server-verifiable X25519 possession.
- [ ] Step 8: Test the operation-time boundary: 300-second nominal lifetime, 30-second monitored skew, 330-second maximum effective interval, no post-expiry grace, single-use operation ID, and rejection of excessive/unknown clock skew.
- [ ] Step 9: Validate contiguous history and exact capacity. Exercise maximum 256-device/64-epoch serialized manifests, 4096-transition and 64 MiB boundaries, 8 MiB entry/page limits, 75 percent warnings, and HISTORY_CAPACITY_REACHED before append. No truncation or compaction.
- [ ] Step 10: Run node --test test/issue-65-recovery-manifest-v2.test.js test/issue-65-recovery-history-v2.test.js test/issue-65-recovery-authorization.test.js test/issue-65-recovery-package-compromise.test.js test/issue-65-recovery-history-capacity.test.js test/rootark-zk-1.test.js test/issue-65-zk-keyring.test.js. Expected: pass; chain validity is not freshness or deployment proof.
- [ ] Step 11: Commit only the completed Phase 2 files after diff review and exact tests; do not push.

## Phase 3 - Mock-Only CAS, Witness, and Admission State Model

**Owner:** Test/crypto contract owner. **Deliverable:** adversarial contract simulation, explicitly unable to prove any real provider.

**Files:** test/support/issue-65-recovery-state-model.js and test/issue-65-recovery-state-model.test.js only, unless an existing test proves a test-only correction is needed. Never import model code from src/, server.js, or browser code.

- [ ] Step 1: Run the existing state-model cases once after code phases stabilize. Expected cases include pendingRevocationBlocksRestoredOldHeadAfterCasCommit, witnessOutageAndRestartPreservePendingGate, onlyExactCommittedOrFinalNoCommitProofResolvesReservation, rejectsStaleOrWrongScopeTerminalReceipt, sameOperationExactBytesAreIdempotentButChangedBytesConflict, concurrentWritersHaveOneWinner, and compromiseRotationNeverPromotesOnUncertainCasOrLosesFinalPath.
- [ ] Step 2: If any behavior lacks a failing case, add that assertion first and observe the RED result before changing the test-only model.
- [ ] Step 3: Ensure a durable pending state is established before ticket return; unresolved reservations block reads, recovery, enrollment, authorization, unwrap, writes, and mutations. Old revision r cannot authorize while a revocation to r+1 is unresolved, even after app-store rollback.
- [ ] Step 4: Accept only the exact signed committed proof or a provably final no-commit proof from a separately trusted linearizable authority. The model must reject application-server-only assertions, stale nonce/head, wrong scope, ambiguous outcomes, and restart without ledger continuity.
- [ ] Step 5: Prove retries accept only identical operation ID/request/manifest/package bytes; changed bytes conflict. Concurrent writers have one winner. Compromise rotation never promotes local state on an uncertain CAS and never silently removes the last recovery path.
- [ ] Step 6: Run node --test test/issue-65-recovery-state-model.test.js. Label the result mock-only in test names/reporting. It must never satisfy a real CAS, witness, admission, crash/restore, or deployment row.
- [ ] Step 7: Commit only test-support files after diff review and exact tests; do not push.

## Phase 4 - Exact-SHA Validation and Independent Follow-Up Review

**Owner:** Implementer gathers evidence; ChatGPT performs the follow-up security review on the exact final SHA. **Deliverable:** reproducible report and explicit pass/blocked matrix.

- [ ] Step 1: Run all nine recovery suites on Windows Node 22 and Ubuntu Node 22 using the exact final SHA:
  node --test test/issue-65-recovery-authorization.test.js test/issue-65-recovery-history-capacity.test.js test/issue-65-recovery-history-v2.test.js test/issue-65-recovery-kdf.test.js test/issue-65-recovery-manifest-v2.test.js test/issue-65-recovery-package-compromise.test.js test/issue-65-recovery-package.test.js test/issue-65-recovery-rootkey-compat.test.js test/issue-65-recovery-state-model.test.js
  Record node --version, platform, SHA, pass/fail/skip counts, and all blocked runs.
- [ ] Step 2: Run focused v1 regressions test/rootark-zk-1.test.js and test/issue-65-zk-keyring.test.js on both Node 22 platforms. Run npm test once on Ubuntu Node 22 or report the exact environment/timeout blocker; do not convert an incomplete run into a pass.
- [ ] Step 3: Re-run the Windows release gate once on exact final SHA. The supplied audit reported 18 pass and 2 fail on an earlier SHA. Compare those failures to a clean equivalent base checkout before classifying them; do not call them unrelated without evidence. If the base comparison cannot be performed safely, report the gate unresolved.
- [ ] Step 4: Run syntax/static/dependency gates required by repository workflow on the exact SHA. Report remote CI separately; CI remoto não confirmado if no hosted result is available.
- [ ] Step 5: Complete the KDF evidence row only with an independent Argon2id13 vector source, supported Node 22 Windows/Linux results, minimum-hardware latency/RSS, and allocation/worker failure evidence. Otherwise keep KDF_PROFILE_VALIDATION_BLOCKED and the profile provisional.
- [ ] Step 6: Before requesting review, confirm only intended files changed, no secrets or generated artifacts were included, git diff --check passes, and the final SHA and test artifacts are recorded.
- [ ] Step 7: Request a read-only ChatGPT follow-up review of the exact final SHA, diff, tests, and blockers. Include the full decision matrix in this plan's final report section. Apply no more than one targeted correction round for a new blocking issue before reporting any remaining blocker.
- [ ] Step 8: Do not push, merge, deploy, close #65, or claim end-to-end Zero-Knowledge recovery.

## Acceptance Matrix

| Acceptance item | Planned evidence | Status after the bounded foundation |
|---|---|---|
| Package parsing, authenticated round trip, scope/tamper rejection | Package and KDF tests; exact envelope limits | Planned; only local library behavior may pass |
| Public authorization separated from client secrets | Manifest tests prove public-only verification; client MAC tests require local keys | Planned |
| Recovery wraps actually decrypt and match authenticated epoch keys | Real HPKE fixtures and history negative/positive tests | Planned; client library scope only |
| Compromised package cannot receive new epoch | Compromise transition tests, exact wrap-set checks | Planned |
| Pending witness state rejects stale r after revocation reservation | Mock state-model RED/GREEN tests | Planned; mock-only |
| Witness base/head wire-schema separation | Independently reviewed normative amendment plus parser tests | Blocked until spec amendment is reviewed |
| KDF tuple approved for production | Independent vector and Node 22 resource/failure evidence | Conditional; profile remains provisional without all evidence |
| v1 rootKey unchanged and no implicit v2 conversion | Compatibility test and call-site inventory | Conditional on no external consumer |
| Shared CAS and independent status authority | Real selected service, pinned key, durable linearizable CAS/status tests | Blocked |
| Witness service and pending gate | Independent witness, pinned bootstrap key, durable reservation-ledger and restart tests | Blocked |
| Device keychain and monotonic high-water | Verified client OS provider and rollback capability tests | Blocked |
| Browser/mobile pairing, export and retention | Separately approved UX and real client runtime | Blocked / owner decision |
| End-to-end protected file recovery and migration | Real authorized client path, ciphertext-only storage, migration approval | Blocked |
| Production, merge, and issue #65 completion | Separate release evidence and approval of all original #65 criteria | Prohibited by current scope; #65 remains open |

## Explicitly Blocked Integrations

- Shared CAS backend and atomic cross-process/cross-host serialization.
- Independently pinned CAS-status authority; truthful terminal result, final cancellation tombstone, and crash/restore ledger proof.
- Independent witness operator, signing key bootstrap/pinning, durable monotonic ledger, reservation persistence, and outage recovery.
- Protected-content read/write admission gate wired to the same per-keyring serialization as CAS.
- OS-backed device private-key storage and atomic high-water/pending/active state. A keychain without rollback metadata still requires a fresh witness read.
- Browser/mobile crypto runtime, trusted pairing channel, replacement-device workflow, and device secure-storage implementation.
- User-facing export, byte read-back, retention confirmation, recovery verification, pairing consent, and compromise UX.
- Existing offline-access policy compatibility if it promises fresh state-dependent access without a witness.
- v1 migration, historical re-encryption, mixed-mode writes, real file decryption, production rollout, and issue #65 closure.
- A safe history checkpoint/rekey or capacity lifecycle beyond the 4096/64 MiB prototype limits.

## Plan Self-Review

- Spec coverage: Sections 12.1-12.3 map to Phases 1-2; 12.4-12.5 map to the test-only Phase 3 model while real providers remain blocked; 12.6 maps to package coverage and rootKey compatibility; 12.7 maps to the threat and integration tables.
- Finding coverage: P1-A public verification has public-only tests; P1-B requires real client-side HPKE opening of every newly added recovery wrap; compromised-package forward rotation and witness pending/read gates have negative cases.
- Review-focus coverage: every one of the five high-risk input classes above points to exact test files; no test or mock claims real infrastructure.
- Proportion: phases follow the accepted four deliverables; the plan does not specify function bodies or invent a service provider.
- Boundary check: UI, persistence, deployment, data migration, and end-to-end content recovery remain blocked; no change is authorized before plan approval.
- Validation scope: documentation-only plan preparation runs no application tests. After acceptance, run only the named focused suites and the exact cross-platform/final gates above.

## Unresolved Questions for the Next Gate

1. Will the independent reviewer approve a normative amendment that gives the committed package-base witness receipt its own exact type string and signature domain, distinct from fresh-head/pending receipts?
2. Does any external consumer require the legacy rootKey in recovery state? Any such consumer blocks v2 omission.
3. Which minimum supported Node 22 hardware and independent Argon2id13 vector implementation are available? If none are selected, keep the KDF validation gate blocked.
4. Does the existing product promise state-dependent offline access while a reservation is pending? If yes, that owner policy must be resolved before runtime admission.
5. Which operators and services, if any, will own shared CAS, terminal status, witness key bootstrap, and durable reservation ledger? None is selected in this plan; no deployment is assumed.
6. What separately reviewed capacity lifecycle will prevent eventual history exhaustion from blocking safety actions? It is outside this foundation.

## Approval Handoff

The reviewed source is docs/superpowers/specs/2026-10-19-rootark-dual-recovery-design.md at b5b31b31e407df02cdc023d46d841714e2bc5622. ChatGPT's supplied verdict accepts only bounded execution planning. This plan requires user approval before product-code changes. It recommends the direct, sequential Codex method; do not use subagents unless they are proven in runtime metadata and a concrete phase benefits from delegation. Please review this plan and confirm it captures the intended scope before any implementation begins.

## Follow-up Audit Correction Record

The user then supplied a source-level audit for reported head `39748936a9624624fa0ee909980e5f7bb2c05ef3` and explicitly requested test-first correction of its P1-A, P1-B, and witness schema findings in this existing E: worktree. This is scoped authorization for those corrections only; the earlier review still does not authorize provider selection, runtime integration, production, or issue #65 closure.

- **P1-A, public transition verifier:** the public path now validates only canonical public state, scope, transition structure, previous-state signer, and revision. It no longer checks epoch-key possession. Its input rejects any field outside `previousManifest`, `nextManifest`, `expectedScope`, and `retainedIdentifiers`, including epoch keys and recovery-package private keys. Prior-key coverage, new-key independence, and MAC verification stay in the client-only MAC proof. Public-only revocation and compromise tests pass; unauthorized actor, epoch-key input, package-private-key input, and missing client keys are negative cases. The reviewer supplied the baseline `KEY_COVERAGE_INCOMPLETE` reproduction; the follow-up unknown-secret-field regression was observed RED before the input allowlist change and GREEN afterward.
- **P1-B, recovery wraps:** the history verifier now opens each newly added recovery wrap with the matching client-held package HPKE private key, exact frozen info/AAD context, and expected epoch key. It only reports a complete verified history after the opened 32-byte key matches. Runtime-generated HPKE fixtures replace synthetic positive wraps. Missing package keys, random 32/48-byte wrap bytes, tampered encapsulation, wrong recipient, epoch, key_ref, and missing historical keys are rejected. The synthetic-wrap and misbinding tests were observed RED before the verifier change and GREEN afterward.
- **P2, witness wire format:** immutable package-base snapshots use `rootark-recovery-witness-base/v1` and the `recovery-witness-base/v1` signing domain, with `revision`/`manifest_digest`. Fresh responses use the separately typed `rootark-recovery-witness-head/v1`, with `current_revision`/`current_manifest_digest` and `pending_reservation_id`. The package and history parsers use the base schema; tests reject fresh-head and pending receipts in the base slot. The base-receipt spec amendment is a working-tree change and remains subject to the requested exact-SHA independent review.

The audit reported 60/60 tests on Windows Node 24.14.1 at its reviewed state, not Node 22.22.1, and did not independently verify the supplied Git SHA. After the corrections, the nine focused recovery suites passed 73 tests on Windows Node 22.22.1 before the final public-input allowlist addition; its targeted four-test check passed afterward. Exact-SHA Windows and Ubuntu Node 22 runs, Ubuntu `npm test`, Windows release-gate/base comparison, and an independent review remain pending. The Node 22 KDF vector/minimum-hardware evidence remains provisional. No shared CAS, status authority, witness service, device keychain/high-water store, app admission gate, browser/mobile client, migration, or production integration was added.
