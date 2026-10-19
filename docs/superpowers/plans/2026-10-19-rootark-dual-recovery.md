# Root.ark Dual Recovery Bounded Crypto Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Do not start product-code work until the owner accepts this written plan.

**Goal:** Add a bounded, CommonJS Node crypto library for the accepted dual-recovery protocol without enabling server, client-runtime, or production recovery.

**Architecture:** Reuse the existing `rootark-zk-1` primitives where their suite and encoding contracts match. Add recovery-specific package, authorization, manifest, history, and KDF modules; run the synchronous libsodium KDF only in a single bounded worker. Keep CAS, witness, content admission, and crash behavior in clearly labeled test-only models until their real providers are selected and verified.

**Tech Stack:** Repository CommonJS, Node.js 22, built-in `node:test`, existing `cborg`, `@hpke/*`, and pinned `libsodium-wrappers-sumo` / `libsodium-sumo` 0.8.4. No dependency or lockfile changes are planned.

**Spec:** `docs/superpowers/specs/2026-10-19-rootark-dual-recovery-design.md`, accepted for bounded execution planning at `b5b31b31e407df02cdc023d46d841714e2bc5622` (parent `d1af0424678f85b27a1cf811dc2c0e94cce6713a`).

## Global Constraints

- Treat Section 12 of the cited revision-3 spec as normative; preserve the owner's two recovery methods and shared-CAS target.
- Keep the KDF candidate exactly Argon2id v1.3, 16-byte salt, 32-byte output, opslimit 3, and memlimit 268435456 bytes. No downgrade, parameter negotiation, or synchronous main-thread call.
- Parse and enforce the 8 MiB envelope cap, 7 MiB decrypted-payload cap, exact deterministic-CBOR schema, and exact KDF tuple before starting a KDF worker.
- Preserve the existing RFC 9180 HPKE suite (X25519/HKDF-SHA256/AES-256-GCM), AES-256-GCM package encryption, Ed25519 authorization, and domain-separated digest inputs exactly as specified.
- Enforce at most 256 devices, 64 epochs, 4096 history transitions, 8 MiB per history entry, 64 MiB total history, and 8 MiB per returned page. Warn at 75%; never prune, checkpoint, or truncate history in this plan.
- Keep v1 `rootKey` behavior unchanged. The v2 parser rejects an unexpected `rootKey`; any external consumer blocks omission pending a separately reviewed format.
- Generate passwords, keys, salts, and ciphertext in tests at runtime. Never commit, print, log, or persist user secrets or secret-looking test fixtures. Do not write package exports or test artifacts outside the E: worktree.
- Do not alter `src/crypto/rootark-zk-1.js` or `src/crypto/rootark-zk-keyring.js` unless a failing test proves a required shared primitive is missing; any such change must remain backward compatible and be reviewed as a scope change.
- No route, database, shared CAS, CAS-status authority, witness service, OS keychain, high-water store, browser/mobile flow, retention/pairing/compromise UI, migration, or real content recovery is included.
- A pure history verifier proves only the supplied chain. It never reports freshness or current authorization without a real independently pinned witness.
- A mock state model is test-only evidence. It cannot satisfy integration, deployment, rollback, content-admission, keychain, CI, or issue #65 acceptance.
- Before implementation, query AI Memory through MCP for current `bielxdh3-root.ark` decisions and constraints; apply Ponytail full and the applicable Superpowers execution skill. UI-UX-PRO-MAX was checked and no UI search or rules are applied because this scope has no interface work; load and apply it before any separately approved UI phase. Do not use Dual Agents. Use a direct Codex worker by default; use a native subagent only if its configured identity/model/effort can be verified and the phase benefits from delegation.
- Work only in `E:\servidor\.worktrees\zk-dual-recovery-20261019` on `cdx/rootark-dual-recovery-20261019`. The starting implementation baseline is the exact spec commit above. Preserve the primary checkout.
- Make one intentional commit per completed phase with exactly one `Co-authored-by: Codex <codex@openai.com>` trailer. Do not push, create/update a PR, merge, deploy, close or edit issue #65, or update `docs/plan-tree.md` under this plan.

## Review Focus

1. Malformed, noncanonical, duplicate-field, oversized, or unsupported-profile packages must fail before KDF work and return no plaintext — `test/issue-65-recovery-package.test.js` and `test/issue-65-recovery-kdf.test.js`.
2. Wrong password, altered AAD/ciphertext/tag, swapped scope, and substituted envelope bytes must fail authentication or scope checks — `test/issue-65-recovery-package.test.js`.
3. Wrong prior-state actor, unknown operation, stale credential, expired operation, target-key mismatch, and replay must fail closed — `test/issue-65-recovery-manifest-v2.test.js`, `test/issue-65-recovery-authorization.test.js`, and `test/issue-65-recovery-state-model.test.js`.
4. Missing, altered, reordered, oversized, stale, or forked history must never be described as current/fresh — `test/issue-65-recovery-history-v2.test.js` and `test/issue-65-recovery-state-model.test.js`.
5. Missing old epochs, last-authority loss, unresolved reservations, CAS/witness outage, and history exhaustion must preserve the block instead of silently downgrading recovery — `test/issue-65-recovery-package-compromise.test.js`, `test/issue-65-recovery-history-capacity.test.js`, and `test/issue-65-recovery-state-model.test.js`.

---

## Repository-Grounded File Map

| Path | Responsibility / owner |
|---|---|
| `src/crypto/rootark-zk-1.js` | Existing deterministic CBOR, AES-GCM, HPKE, authorization, KDF, and secret-clearing helpers; reuse only compatible APIs. No planned modification. |
| `src/crypto/rootark-zk-keyring.js` | Existing v1 keyring and `rootKey`; preserve behavior. No planned modification. |
| `src/crypto/rootark-zk-recovery-kdf.js` | Recovery-only input bounds, one-active-worker rule, timeout/error mapping, and fixed candidate tuple; crypto owner. |
| `src/crypto/rootark-zk-recovery-kdf-worker.js` | Worker entry that calls the existing synchronous libsodium helper with only the fixed tuple; crypto owner. |
| `src/crypto/rootark-zk-recovery-package-v1.js` | Exact envelope schema, activation/AAD digests, parse-before-KDF, payload/key coverage checks, and package round-trip; crypto owner. |
| `src/crypto/rootark-zk-recovery-manifest-v2.js` | Manifest schema/digests, previous-state actor matrix, signing, verification, expiry, and compromise transition; crypto owner. |
| `src/crypto/rootark-zk-recovery-authorization.js` | Target challenge/response encoding, Ed25519 response verification, scope/expiry/challenge-ID binding; replay consumption is outside this stateless module; crypto owner. |
| `src/crypto/rootark-zk-recovery-history-v2.js` | Contiguous history verification and count/byte warning and hard limits; crypto owner. |
| `test/issue-65-recovery-kdf.test.js` | Candidate profile bounds, worker concurrency/failure, parse-before-worker assertion, and runtime-only test inputs. |
| `test/issue-65-recovery-package.test.js` | Exact envelope, parser bounds, witness-base-receipt check, AAD/digest binding, payload validation, and round-trip; full activation binding is tested with the manifest verifier in Phase 2. |
| `test/issue-65-recovery-rootkey-compat.test.js` | v1 behavior unchanged; v2 rejects implicit v1 conversion and an unexpected `rootKey`. |
| `test/issue-65-recovery-manifest-v2.test.js` | Manifest validation, signatures/MAC, operation matrix, expiry, and revisions. |
| `test/issue-65-recovery-authorization.test.js` | Target proof transcript, expected challenge, scope, expiry, challenge binding, and proof-boundary behavior. |
| `test/issue-65-recovery-history-v2.test.js` | Chain continuity, digest/signature validation, and malformed-history failures. |
| `test/issue-65-recovery-package-compromise.test.js` | Forward epoch rotation, exclusive new-key wraps, and missing-authority/key failures. |
| `test/issue-65-recovery-history-capacity.test.js` | Maximum-size cases, 75% warning, hard caps, and no pruning. |
| `test/support/issue-65-recovery-state-model.js` | Explicitly fake, deterministic test-only CAS/witness/status/admission model. |
| `test/issue-65-recovery-state-model.test.js` | Race, pending, crash/restart, retry, stale-head, outage, and rotation contracts against that fake model only. |

No `test/integration/issue-65-recovery-cas-witness.test.js`, `test/integration/issue-65-recovery-admission-gate.test.js`, device-storage test, or content-E2E test is created in this foundation. Those require real selected providers and remain blocked.

## Shared Interfaces and Error Contract

The names below are the plan's cross-module contract. Inputs use `Buffer` for encoded bytes, Node `KeyObject` for Ed25519 keys, and the key objects returned by the existing HPKE suite. Keep these CommonJS exports small and do not expose a caller-selectable KDF profile.

| API | Exact behavior |
|---|---|
| `deriveRecoveryKeyBounded({ password, salt }) -> Promise<Buffer>` | `password` is the exact UTF-8 string (1–1024 bytes); `salt` is exactly 16 bytes. Resolves with exactly 32 bytes. A concurrent request fails immediately with `KDF_BUSY`; no queue. |
| `parseRecoveryPackageV1({ envelopeBytes, expectedScope }) -> Promise<ParsedRecoveryPackage>` | Rejects over-limit/noncanonical/wrong-scope/unknown-field/unsupported-profile bytes before deriving. It does not expose plaintext or secrets. |
| `createRecoveryPackageV1({ password, payload, pinnedWitness }) -> Promise<Buffer>` | Creates the exact v1 envelope with fresh salt/nonce and the fixed KDF/AEAD maps; validates the complete payload, epoch coverage, and signed base receipt against `{ keyId, publicKey }` before returning exact bytes. |
| `openRecoveryPackageV1({ password, envelopeBytes, expectedScope, pinnedWitness }) -> Promise<RecoveryPayload>` | Calls the strict parser first, then the bounded KDF, authenticates exact AAD, cross-checks every duplicated outer-header/payload field, and validates every epoch entry and signed base receipt against the caller-supplied pinned witness key before returning it. The function does not bootstrap or pin that key. |
| `recoveryPackageEnvelopeDigest(envelopeBytes) -> Buffer` | Computes the Section 12.2 domain-separated digest over the exact encoded envelope bytes. |
| `verifyRecoveryPackageActivation({ envelopeBytes, payload, verifiedActivationManifest }) -> true` | Recomputes the exact envelope and activation-context digests and checks scope, package ID, base head, activation revision, operation ID, and recovery key IDs against a transition the caller already verified. A mismatch throws `INVALID_RECOVERY_PACKAGE`; this helper does not verify the manifest signature itself. |
| `signRecoveryTransitionV2({ priorVerifiedHistory, proposedCore, actorPrivateKey, manifestMacKey, now, clockHealthy }) -> Promise<SignedManifestV2>` | `priorVerifiedHistory` is null only for `initialize`; otherwise it is the complete chain-validation result through the exact expected prior head. Checks operation/challenge/device/package/key/wrap IDs against retained history, the exact actor matrix, and the live admission clock window before signing. `manifestMacKey` is the key for the proposed current epoch, including a newly generated key during `compromise-package`. |
| `verifyRecoveryTransitionPublicV2({ previousManifest, nextManifest, expectedScope, retainedIdentifiers }) -> PublicTransitionProof` | Verifies exact schema, scope, prior-state signer, public signature, operation invariants, ID non-reuse against the complete supplied history inventory, and next revision/digest. It checks stored time-field shape and maximum 300-second nominal duration, but does not compare with the current clock or verify the MAC. Historical transitions remain verifiable after expiry. |
| `verifyRecoveryTransitionMacV2({ publicTransitionProof, manifestMacKey }) -> true` | Verifies the MAC only after the public transition proof succeeds. `manifestMacKey` is the key for `nextManifest.current_epoch`; recovery opens newly added wraps only after public checks, then supplies the corresponding key. |
| `verifyRecoveryAdmissionWindowV2({ issuedAt, expiresAt, now, clockHealthy }) -> true` | Applies the live admission rule: positive lifetime at most 300 seconds, monitored clock health, and `issuedAt - 30 <= now <= expiresAt` with no post-expiry grace. The 330-second worst-case real interval assumes the externally monitored 30-second skew bound; this helper does not prove CAS/witness clock health. |
| `createTargetPopChallenge({ scope, operationId, targetDeviceId, hpkePublicKey, authorizationPublicKey, issuedAt, expiresAt }) -> Promise<TargetPopChallenge>` | Generates the CSPRNG challenge and ID, canonical context, and HPKE ciphertext bound to the target keys and operation. The authorizer retains the expected challenge locally. |
| `verifyTargetPopResponse({ challenge, challengeContext, response, expectedScope, expectedDeviceKeyDigest, now }) -> Promise<TargetPopProof>` | Requires the authorizer's locally retained challenge; verifies exact challenge equality, target Ed25519 signature, target-key/scope binding, and expiry. It cannot prove the response arrived over an authenticated pairing channel or prove human consent. |
| `verifyRecoveryHistory({ recoveryPayload, envelopeBytes, transitionEntries, expectedHead, pinnedWitness }) -> Promise<{ headManifest, headDigest, revision, usedIdentifiers, packageAuthorityStatus }>` | Verifies the package's signed base manifest and witness receipt against the caller-supplied pin, binds the exact envelope bytes to the first activation transition, then consumes one canonical signed-manifest entry at a time (each at most 8 MiB). It checks public signature/state before opening newly added recovery wraps, verifies each manifest MAC with the matching epoch key, and rejects identifiers reused anywhere in retained history. `packageAuthorityStatus` reports whether this package remains authorized at the supplied head. Output is chain validity only, never freshness/current state. |
| `checkRecoveryHistoryCapacity({ transitionCount, historyBytes, nextEntryBytes }) -> { usedTransitions, usedBytes, maxTransitions, maxEntryBytes, maxHistoryBytes, warning }` | Exposes exact use and hard limits; returns `warning: true` at or above 75% of either count/byte cap; throws `HISTORY_CAPACITY_REACHED` only when the proposed append exceeds an entry/count/total cap. Never prunes. |

Pure-library functions use the existing `RootarkZkError` with these exact codes: `UNSUPPORTED_KDF_PROFILE`, `KDF_BUSY`, `RECOVERY_KDF_FAILED`, `RECOVERY_PACKAGE_TOO_LARGE`, `RECOVERY_PAYLOAD_TOO_LARGE`, `INVALID_RECOVERY_PACKAGE`, `AUTHENTICATION_FAILED`, `SCOPE_MISMATCH`, `KEY_COVERAGE_INCOMPLETE`, `COMPROMISE_RECOVERY_UNAVAILABLE`, `UNKNOWN_RECOVERY_OPERATION`, `UNAUTHORIZED_ACTOR`, `AUTHORIZATION_EXPIRED`, `INVALID_TARGET_POP`, `HISTORY_INVALID`, and `HISTORY_CAPACITY_REACHED`. The fake Phase 3 model uses `PENDING_RESERVATION`, `COMMITTED_UNWITNESSED`, `ROLLBACK_RESISTANCE_INCOMPLETE`, and `IDEMPOTENCY_CONFLICT` as test-only contract outcomes; these are not real service guarantees or new runtime APIs. `HISTORY_CAPACITY_WARNING` is a warning state, not a successful recovery or a reason to block earlier than the hard cap.

## Pre-Implementation Gate (No Product Code)

1. Confirm the owner has accepted this plan; the prior review authorizes planning only.
2. On each execution runner, record `node --version` as Node 22.x and `npm --version`; use the existing `.github/workflows/security-regression.yml` Ubuntu and Windows 2022 Node 22 jobs as the cross-platform targets.
3. Run `npm ls libsodium-wrappers-sumo libsodium-sumo --all` after a clean `npm ci`; require both resolved versions to remain 0.8.4 and verify the lockfile is unchanged.
4. Identify the minimum supported hardware and an already available, independent Argon2id v1.3 reference implementation on both OS targets. Do not add a product dependency or embed password/key inputs in the repository to obtain a vector. Use fresh in-memory values through a protected pipe, compare outputs without logging them, and record only reference/tool versions, hashes, elapsed time, peak process RSS, and pass/fail. If either prerequisite is unavailable, record `KDF_PROFILE_VALIDATION_BLOCKED`; the tuple remains provisional and no fallback is permitted.
5. If the preflight command fails, preserve the exact failure as a blocker; do not install extra crypto packages, change the profile, or substitute Node 24 evidence.

## Phase 1 — Recovery Package and Bounded KDF

**Owner:** Crypto module owner. **Deliverable:** standalone package/KDF modules with unit coverage; no runtime caller.

**Files:** the two KDF modules, package module, and the three KDF/package/rootKey tests in the file map.

- [ ] **Step 1: Write the KDF red tests.** Add `usesFixedArgon2id13ProfileAndReturns32Bytes`, `returnsKdfBusyWithoutQueueingSecondDerivation`, and `mapsWorkerStartupErrorExitTimeoutAndAllocationFailureToRecoveryKdfFailed`. Use a `node:test` Worker test double to inject failures; keep the seam private and add no public test-control option. Generate input in memory; no password or key fixture is committed.
- [ ] **Step 2: Run the KDF tests before implementation.** Run `node --test test/issue-65-recovery-kdf.test.js`. Expected: fail because the recovery KDF module/export is absent. Save the failure output in the phase report without secrets.
- [ ] **Step 3: Implement the fixed-profile worker path.** Add `deriveRecoveryKeyBounded` and the worker entry; pass only bounded inputs, call the existing synchronous `deriveRecoveryKey` with opslimit 3 / memlimit 268435456 inside the worker, enforce one active request, terminate and clear pending state on every terminal path, and never log inputs or outputs.
- [ ] **Step 4: Run the KDF tests.** Run `node --test test/issue-65-recovery-kdf.test.js`. Expected: pass; an overlapping request returns `KDF_BUSY` without starting a second worker; injected worker failures return `RECOVERY_KDF_FAILED` and leave the service able to report its next state honestly.
- [ ] **Step 5: Repeat the bounded v1 inventory and write package/compatibility red tests.** Run `rg -n 'rootKey|createAccountKeyring|exportManifest|rootark-zk-keyring' --glob '*.js' --glob '!node_modules/**' --glob '!dist/**'`; record repository call sites without claiming external consumers are known. Add `rejectsMalformedAndOversizedEnvelopeBeforeKdf`, `roundTripsExactEnvelopeAndDomainSeparatedDigests`, `rejectsWrongPasswordTamperingAndScopeMismatch`, `requiresContiguousCompleteEpochKeys`, `rejectsInvalidOrWrongScopeBaseWitnessReceipt`, `digestChangesForOneByteEnvelopeSubstitution`, and `rejectsV1AndUnexpectedRootKeyInV2WithoutChangingV1Shape`. In `test/issue-65-recovery-kdf.test.js`, add `rejectsUnsupportedKdfTupleBeforeWorkerStarts` by mocking the internal KDF export and asserting the call count stays zero. Cover every Section 12.2 field and 8 MiB outer / 7 MiB inner caps.
- [ ] **Step 6: Run the package tests before implementation.** Run `node --test test/issue-65-recovery-kdf.test.js test/issue-65-recovery-package.test.js test/issue-65-recovery-rootkey-compat.test.js`. Expected: the KDF worker unit tests pass, while the package-open/profile-order/compatibility tests fail because the recovery package module and exports are absent; the existing v1 test must continue to pass.
- [ ] **Step 7: Implement the package module.** Reuse existing deterministic-CBOR, AES-GCM, error, and best-effort secret-clearing helpers where compatible. Validate sizes/schema/profile/scope before KDF; after decryption verify the pinned base-receipt signature and exact payload key coverage; return and digest the exact encoded envelope bytes. Keep the verified-manifest activation binding helper in Phase 2, and keep file export/read-back and retention confirmation outside this library.
- [ ] **Step 8: Run focused new and existing regression tests.** Run `node --test test/issue-65-recovery-kdf.test.js test/issue-65-recovery-package.test.js test/issue-65-recovery-rootkey-compat.test.js test/rootark-zk-1.test.js test/issue-65-zk-keyring.test.js`. Expected: all pass with v1 keyring behavior and rootKey assertions unchanged.
- [ ] **Step 9: Commit Phase 1.** Commit only the Phase 1 source/tests after `git diff --check` and review of the file list; do not push.

**Phase 1 security boundary:** Password and decrypted payload remain client-only. A library round-trip proves byte identity/readability, not user retention. No KDF profile approval is claimed until the cross-platform independent-reference and minimum-hardware gate passes.

## Phase 2 — Manifest, Target Authorization, and Offline History Verifier

**Owner:** Crypto module owner. **Deliverable:** pure signed-state and chain-verification library; no CAS or witness integration.

**Files:** manifest-v2, authorization, and history-v2 modules plus their tests, the package-compromise test, and the history-capacity test.

- [ ] **Step 1: Write manifest red tests.** Add `rejectsEveryDisallowedActorOperationPair`, `acceptsOnlyPriorStateSignerAndNextRevision`, `rejectsUnknownOperationAndAdmissionClockBoundary`, `acceptsExpiredSignedTransitionDuringHistoricalVerification`, `rejectsReusedIdentifiersFromPriorHistoryInventory`, `bindsVerifiedPackageActivationToExactEnvelopeBytes`, and `compromisePackageRequiresReplacementAndAtomicForwardRotation`. Assert exact schema/digest, both actor columns for every operation, operation/challenge/device/package/recovery-key/wrap ID non-reuse against a complete verified prior-history inventory, only key rotation increments epoch, signature/MAC/scope failures, the 300-second nominal lifetime, 30-second skew, exact 330-second boundary, no post-expiry grace, and continued validity of already-committed history after expiry. Assert package actors are limited to `recover-device`, ordinary replacement cannot substitute for compromise, and unapproved voluntary device-only revocation is denied. For package activation, create bytes, sign/verify the public transition, pass only the verified result to the binder, then change one byte and require `INVALID_RECOVERY_PACKAGE`. The compromise assertion requires every prior epoch key and exactly one recovery wrap per prior/fresh epoch to the replacement package, with no fresh-epoch wrap to the compromised package.
- [ ] **Step 2: Run the manifest test before implementation.** Run `node --test test/issue-65-recovery-manifest-v2.test.js test/issue-65-recovery-package-compromise.test.js`. Expected: fail because the v2 recovery manifest module does not exist; the package byte-binding test remains red until verification is implemented.
- [ ] **Step 3: Implement manifest-v2 signing and verification.** Add the exact operation matrix, deterministic manifest/request digests, previous-state signer validation, signature and separated MAC verification, operation/time-field/revision rules, and compromise transition invariants. Require a complete verified prior-history context to prevent identifier reuse. Admission-time validation checks the live 330-second maximum acceptance window and clock health; historical signature/state validation never rejects an already committed transition merely because its admission window expired. Never accept a new key as its own authorizer.
- [ ] **Step 4: Run manifest and compromise tests.** Run the same command. Expected: pass; missing epoch material yields `KEY_COVERAGE_INCOMPLETE`, absent trustworthy surviving authority yields `COMPROMISE_RECOVERY_UNAVAILABLE`, and the new epoch is never wrapped to the compromised package.
- [ ] **Step 5: Write target-proof red tests.** Add `bindsChallengeToScopeTargetAndOperation`, `acceptsOnlyMatchingChallengeAndTargetSignature`, and `publicTranscriptAloneDoesNotProveTargetHpkePossession`. Cover 32-byte challenge / 16-byte ID, wrong target key or operation/scope, changed challenge, bad Ed25519 signature, and expiry. Operation/challenge replay consumption belongs to the Phase 3 state model, not this stateless module. Include a case showing a public ciphertext/signature transcript alone cannot satisfy the local author's expected-challenge check.
- [ ] **Step 6: Run target-proof tests before implementation.** Run `node --test test/issue-65-recovery-authorization.test.js`. Expected: fail because the recovery authorization module does not exist.
- [ ] **Step 7: Implement the target challenge/response module.** Use the frozen HPKE suite and exact domain strings; require the authorizer's retained challenge for response verification. Do not claim server-verifiable X25519 possession, pairing-channel authenticity, or user-consent UX.
- [ ] **Step 8: Run target-proof tests.** Run `node --test test/issue-65-recovery-authorization.test.js`. Expected: pass for local challenge/Ed25519 checks only; integration acceptance stays blocked.
- [ ] **Step 9: Write history and capacity red tests.** Add `acceptsCompleteContiguousHistoryOnly`, `rejectsMissingReorderedDuplicateAlteredAndTruncatedTransitions`, `rejectsIdentifierReuseAcrossSignedHistory`, `rejectsDifferentValidEnvelopeUnderSamePackageId`, `marksRevokedBasePackageUnauthorizedAtHead`, and `warnsAt75PercentAndRejectsOnlyFirstOverLimitAppend`. Cover a wrong prior signer; expired but valid historical operations; 4096/4097 transitions; 8 MiB / first over-entry; 64 MiB / first over-total; per-entry paging capped at 8 MiB; and exact serialized sizes for 256 devices / 64 epochs. Assert no pruning or checkpoint behavior exists.
- [ ] **Step 10: Run history tests before implementation.** Run `node --test test/issue-65-recovery-history-v2.test.js test/issue-65-recovery-history-capacity.test.js`. Expected: fail because the history module is absent.
- [ ] **Step 11: Implement chain verification and capacity checks.** Start from the package's signed base manifest and witness receipt verified against the supplied pin; bind `envelopeBytes` to the first package activation transition. Consume one canonical encoded transition entry at a time, rejecting any entry above 8 MiB. For each transition, validate public signature/state and identifier non-reuse first; only then open newly added recovery wraps and verify the manifest MAC using the corresponding epoch key. Historical expiry does not invalidate a committed transition. Enforce exact digest/signer/operation continuity and Section 12.4 bounds, report exact used bytes/count and hard limits, warn at 75%, and throw `HISTORY_CAPACITY_REACHED` only when an append would exceed a hard limit. Return package authority status at the supplied head; do not confuse a valid chain with authorization after the package was revoked.
- [ ] **Step 12: Run all Phase 2 tests and relevant existing crypto tests.** Run `node --test test/issue-65-recovery-manifest-v2.test.js test/issue-65-recovery-authorization.test.js test/issue-65-recovery-history-v2.test.js test/issue-65-recovery-package-compromise.test.js test/issue-65-recovery-history-capacity.test.js test/rootark-zk-1.test.js test/issue-65-zk-keyring.test.js`. Expected: pass; chain validity never implies freshness or a deployed rollback guarantee.
- [ ] **Step 13: Commit Phase 2.** Commit only Phase 2 source/tests after diff and error-surface review; do not push.

**Phase 2 security boundary:** The verifier authenticates supplied history from the package snapshot only. It does not fetch a head, cancel a reservation, verify CAS, authenticate a pairing channel, or decide that an offline client is current.

## Phase 3 — Test-Only Recovery State-Machine Contracts

**Owner:** Test/crypto contract owner. **Deliverable:** adversarial logical tests over an explicitly fake model; no production state adapter.

**Files:** `test/support/issue-65-recovery-state-model.js` and `test/issue-65-recovery-state-model.test.js` only.

- [ ] **Step 1: Write red contract scenarios.** Add `pendingRevocationBlocksRestoredOldHeadAfterCasCommit`, `witnessOutageAndRestartPreservePendingGate`, `onlyExactCommittedOrFinalNoCommitProofResolvesReservation`, `rejectsStaleOrWrongScopeTerminalReceipt`, `sameOperationExactBytesAreIdempotentButChangedBytesConflict`, `concurrentWritersHaveOneWinner`, and `compromiseRotationNeverPromotesOnUncertainCasOrLosesFinalPath`. Assert reservation closes admissions before ticket return; committed-but-unwitnessed revocation blocks stale `r` and proposed `r+1`; restoring the app store to `r` cannot authorize the revoked actor; pending survives outage/restart; stale nonce, wrong scope/head, or app-server-only status cannot resolve a reservation; final not-committed proof requires expiry+30 seconds, head `r`, no operation result, durable tombstone, and a fresh committed-head read before `r` is usable; changed retry bytes return `IDEMPOTENCY_CONFLICT`; uncertain compromise CAS never promotes local keys; missing last authority/epoch returns the exact fail-closed error.
- [ ] **Step 2: Run the state-model test before implementation.** Run `node --test test/issue-65-recovery-state-model.test.js`. Expected: fail because the test-only model is absent.
- [ ] **Step 3: Implement only the test support model.** Name fake stores/authorities with `Fake` or `Model`, expose deterministic transition controls for crash/restart/outage/race injection, and keep all model files under `test/support/`.
- [ ] **Step 4: Run the state-model tests.** Run `node --test test/issue-65-recovery-state-model.test.js`. Expected: pass as contract simulation. Test output and documentation must say `mock-only`; no simulated pass is reported as CAS, witness, admission, crash-recovery, or deployment proof.
- [ ] **Step 5: Commit Phase 3.** Commit only test support and its tests after diff review; do not push.

**Phase 3 security boundary:** No test-only code is imported by `src/`, `server.js`, a client runtime, or a release gate. The real CAS, status authority, witness, content admission, and client high-water requirements remain blocked.

## Phase 4 — Exact-SHA Validation and Independent Security Review

**Owner:** Implementer gathers evidence; a separate reviewer examines the exact resulting commits. **Deliverable:** reproducible report and explicit pass/block status; no new runtime scope.

- [ ] **Step 1: Run all focused recovery tests on Node 22.** Run:

  `node --test test/issue-65-recovery-kdf.test.js test/issue-65-recovery-package.test.js test/issue-65-recovery-rootkey-compat.test.js test/issue-65-recovery-manifest-v2.test.js test/issue-65-recovery-authorization.test.js test/issue-65-recovery-history-v2.test.js test/issue-65-recovery-package-compromise.test.js test/issue-65-recovery-history-capacity.test.js test/issue-65-recovery-state-model.test.js`

  Expected: all pure-library and mock-only contract tests pass on Windows 2022 Node 22 and Ubuntu Node 22. Capture exact runtime versions and commit SHA; never copy secrets or raw KDF inputs to the report.
- [ ] **Step 2: Run repository validation on the same source SHA.** On Ubuntu Node 22 run `npm run validate:syntax`, `npm test`, `npm run validate:artifacts`, and `npm run validate:dependencies`. On Windows 2022 Node 22 run `npm run validate:release-gate`. Also run `git diff --check` and verify `git status --porcelain` is empty after generated artifacts are handled.
- [ ] **Step 3: Close the KDF evidence gate.** Attach independent-vector source/implementation version, Node 22 OS, minimum hardware identity, elapsed time, peak RSS, worker error/timeout/allocation-failure behavior, and parsing-before-allocation evidence. If any required environment/reference is unavailable, report `KDF_PROFILE_VALIDATION_BLOCKED`; do not weaken or freeze the candidate profile.
- [ ] **Step 4: Review every Section 12 requirement against the phase tests.** Confirm package exact bytes/format, rootKey compatibility, all authority-matrix rows, target proof limits, complete history/capacity, crash/idempotency/pending contracts, compromise forward rotation, and the remaining integration blocks. Any uncovered requirement is a blocker to the bounded-library claim.
- [ ] **Step 5: Request the independent security review on exact local SHA(s).** Supply the plan commit plus implementation commit list, one-file/per-phase diffs, commands and results for each OS, KDF evidence, and the block matrix. The reviewer must verify no mock or local result is represented as real CAS/witness/keychain/content recovery. Correct blocking findings in one targeted cycle, rerun only affected validation, and submit the new exact SHA; keep non-blocking limitations explicit.

## Acceptance Matrix and Deferred Integrations

| Requirement | Bounded-foundation evidence | Still blocked after this plan |
|---|---|---|
| Package/KDF | Strict parser, exact bytes/AAD/digests, local round-trip, worker concurrency/failure tests; Node 22 cross-platform profile evidence only if the preflight inputs exist. | User retention/export UX; production approval of KDF profile if independent verifier/minimum hardware evidence is missing. |
| Manifest/authorization | Pure signatures/MAC, prior-state actor matrix, target challenge and Ed25519 transcript, admission-time boundary tests, and rotation invariants; replay/idempotency behavior is exercised only by the fake Phase 3 model. | Pairing transport, human consent UX, server authorization endpoint, actual trusted-device runtime. |
| History/rollback | Pure contiguous-chain verification and hard capacity accounting. | Fresh-head witness, independent bootstrap/pinning, monotonic durable ledger, real restore/cross-process proof. |
| Reservations/access | Fake model tests exercise pending/terminal/idempotency/admission invariants. | Selected shared CAS, independent status authority, separate witness, real protected-content admission serialization, service crash/restore evidence. |
| Device/content recovery | None claimed. | OS secure key storage/high-water, browser/mobile, actual encrypted-file decrypt on both independent paths, v1 migration, production. |
| Product acceptance | Exact local code/security review only. | Merge, release, deployment, issue #65 closure, complete Zero-Knowledge claim, voluntary device-only recovery-policy change. |

The existing plan tree records Phase 9 runtime protocol compatibility as in progress, and GitHub issue #65 is open. This plan does not satisfy or close either item. Do not update `docs/plan-tree.md` until implementation and its evidence exist.

## Plan Self-Review

- **Spec coverage:** Sections 12.1–12.3 map to Phase 1 and Phase 2; 12.4–12.5 map to pure history/state-model tests while all real providers stay blocked; 12.6 maps to package coverage and rootKey compatibility; 12.7 is the deferred-integration matrix; 12.8 maps to the named unit/mock tests; 12.9 and the independent-review decision map to Phase 4.
- **Boundary check:** No phase creates server endpoints, persistence, UI, migration, client key storage, or real content recovery. Freshness is never inferred from an offline chain or mock.
- **Risk check:** The independent KDF verifier and minimum supported hardware are not established by the supplied review or current repository. The plan leaves the profile provisional and names the exact fail-closed outcome rather than guessing a provider, threshold, or dependency.
- **Validation check:** All commands are scoped to named new tests or existing Node 22 gates. This plan-only change runs no application tests; only Markdown/diff and secret-pattern checks apply to the plan artifact itself.

## Approval Handoff

This plan is not implementation authorization. Review this file and confirm that it captures the intended scope before any product code changes. The proposed execution is direct Codex, phase by phase, with no subagents unless a later phase demonstrates a concrete need and configured provenance. A separate security review remains required after implementation; the architecture verdict does not accept runtime, production, deployment, or issue #65 closure.
