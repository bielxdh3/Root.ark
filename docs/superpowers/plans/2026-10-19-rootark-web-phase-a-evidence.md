# Root.ark Web-First Recovery — Phase A Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **This plan is not yet approved for execution.** Apply PONYTAIL, applicable Superpowers skills, and UI-UX-PRO-MAX only when actual UI design enters an independently approved scope.

**Goal:** Establish an auditable, test-backed product policy and browser-eligibility *feasibility* baseline for Root.ark's web-first Zero-Knowledge recovery without adding trusted-device enrollment, persistent secret storage, or live recovery behavior.

**Architecture:** Use documentation, a narrowly scoped, dependency-free CommonJS `node:test` evidence harness, and disposable local browser probes. Preserve the existing accepted Node recovery library untouched. Unknown browser key custody or freshness is explicitly **unverified**, never auto-approved.

**Tech Stack:** Existing Root.ark Node.js 22 / CommonJS / `node:test`; browser APIs examined on real, explicitly identified test installations only if available and consented. Existing Playwright is not installed in the inspected worktree; do not add dependencies or substitute simulated browsers for real evidence.

**Spec:** `docs/superpowers/specs/2026-10-19-rootark-web-trusted-recovery-design.md`, owner-approved in conversation on 2026-10-19 at commit `b3b1f0420bfc95ccb00af6a2cb5ac6adbd055f00`. This approval permits **planning**, not implementation, integration, or publication.

**Scope classification:** Phase A browser feasibility and policy evidence only. The original design separately reserves Packet B for CAS/status/witness and Packet C for temporary protected transfers and Android interoperability. Implementing all three here would bypass their own design and owner approvals.

**Plan status:** `READY_FOR_OWNER_PLAN_REVIEW` once locally validated; `NOT_AUTHORIZED_FOR_EXECUTION` until the owner accepts this exact plan and execution method.

## Global Constraints

- Product: **temporary file transfers**, web first, Android later. **No new native Windows/Linux desktop app**; preserve current unrelated CLI and Android scaffold.
- Owner-approved offline rule: **already downloaded/exported files can be read offline**; new authorizations, recovery, and transfers **require online connectivity and validated fresh authorization**. Locally displayed, already-held bytes cannot be retroactively erased by the server.
- Eligible trusted browsers require independently reviewed, exact platform-specific protected key custody; WebAuthn login, WebAuthn PRF existence, synchronized passkeys, `extractable=false`, software storage and IndexedDB alone are **not sufficient**. Unsupported/unknown is transfer-only.
- Keep **both** independent recovery methods: user-held encrypted emergency package and previously authorized devices. No administrator master key, default person delegate or silent fallback.
- Preserve bounded library source at `7dd1c861d2b570d7bc51ce66e8054bcc431f4c07`, including F-01/F-02 fixes and exact `rootark-zk-1` cryptographic profile. KDF remains provisional; no silent parameter or primitive changes.
- Preserve D-008 30-day trash/backup defaults, 30-day operational logs and 180-day security logs. They **are not** a newly approved transfer lifetime; no TTL values are invented.
- Future sensitive online actions must require **real** CAS/status/witness proof; existing `freshnessProven=false` must not be relabeled by a test mock. Shared CAS provider, witness, status authority, and real admission remain outside this phase.
- No server, browser `public/`, `src/` runtime, Android, sync-client, persistence, auth/2FA, dependency/lockfile, service-worker, or release-configuration changes; no production inspection or real user data. Only specified documentation and `test/` test-only files are in scope.
- No persistence of disposable credentials, passwords, private keys, recovery packages or PRF outputs. No test browser authentication against production. Local probing uses disposable contexts and remains **NOT_RUN** when authenticators/browsers are unavailable; do not automatically install Playwright.
- Use current isolated worktree `E:\servidor\.worktrees\zk-dual-recovery-20261019`, and E:-only temp/cache/test outputs (`E:\Chats\rootark-tests`). Never alter the primary checkout or use sibling worktrees.
- Consult AI Memory via approved MCP/hooks, load PONYTAIL and applicable Superpowers skill workflow before execution. Treat historical notes as context, not authority. The earlier Root.ark work explicitly excluded Obsidian; do not claim its vault was consulted.
- Follow repository `AGENTS.md` and `docs/plan-tree.md`: owner-identifiable Git metadata, narrowly scoped commits, no force push, no remote branch/PR changes, no issue #65 closure or deploy. No unverified native-subagent model/effort/provenance claims. Use one primary Codex agent by default; review independently at the security gate.

## Review Focus

These five often-overlooked cases **must each have the specified negative/positive tests in the owning task**, without claiming a mock validates deployed enforcement.

1. **Unknown PRF and synced credential:** Task 2 — `unknownPrfNeverBecomesTrusted` and `syncedPasskeyDoesNotProveDeviceBoundCustody` keep status `UNVERIFIED`.
2. **Lost/local-restored key store:** Task 2 — `restoredProfileAndDeletedCredentialDoNotClaimRecovery` blocks any authorization claim after an unverifiable profile restore.
3. **Old service worker / offline queue:** Task 3 — `legacyQueueNotNewZkAuthority` and `staleShellNotFreshSecurityState` document existing code behavior; do not turn either into proof of online freshness.
4. **Offline new download vs exported local file:** Task 3 — `downloadedFileNotRevocable` and `offlineSensitiveOperationsBlockedInContract` distinguish these exact categories without changing legacy routes.
5. **False recovery readiness from simulated state:** Task 4 — `unverifiedWitnessAndKdfNeverCountAsReady` requires a blocked verdict despite green unit tests or browser feature detection.

---

## Source map and ownership

| File | Owner task | Purpose |
|---|---|---|
| `docs/product-discovery.md` | Task 1 | Append D-011 (newer web-first/offline policy), preserve historical D-006/D-008/D-009 verbatim |
| `test/issue-65-web-policy-record.test.js` | Task 1 | Assert exact policy decision and independent recovery constraints are recorded |
| `test/support/issue-65-web-capability-evidence.js` | Task 2 | **Test-only** normalized browser capability/evidence classifier; never emits "approved" |
| `test/issue-65-web-capability-evidence.test.js` | Task 2 | Negative feature/attestation/sync/profile-restore fixtures and data-minimization checks |
| `test/support/issue-65-web-local-probe.html` | Task 2 | Optional **local-only**, user-invoked browser capability probe with no background credential creation or network upload |
| `test/fixtures/issue-65-web-offline-contract.json` | Task 3 | Machine-readable, **test-only** online/offline owner policy; not a runtime admission decision |
| `test/issue-65-web-offline-evidence.test.js` | Task 3 | Read-only current-code contract tests and actual file/service-worker/queue behavior checks, no production edits |
| `docs/validation/2026-10-19-rootark-web-phase-a-evidence.md` | Tasks 2–4 | Versioned evidence matrix, coverage and limitations, unresolved real-browser/custody, freshness and KDF gates |

**No Task modifies:** `public/service-worker.js`, `public/client/*`, `src/crypto/*`, `src/routes/*`, `server.js`, `db/*`, `android/*`, `sync-client/*`, `docs/plan-tree.md`, `package*.json` or existing approved dual-recovery spec/plan. Update the plan tree only in a separately authorized follow-up with implemented-and-validated evidence.

## Task 1: Record owner policy without rewriting historic contracts

**Files**
- Modify: `docs/product-discovery.md` (append one new decision after D-010).
- Create: `test/issue-65-web-policy-record.test.js`.

**Interfaces**
- Consumes: approved spec, existing D-006/D-008/D-009, owner approval.
- Produces: stable `D-011` policy record used by Task 3 contract tests and future packet B/C designs.

- [ ] **Step 1: Write failing `node:test` assertions** (`test/issue-65-web-policy-record.test.js`) for `recordsWebFirstTransferPurposeAndOfflineOwnerRule` and `preservesBothRecoveryPathsAndSeparateRetention`. Read the D-011 section from `docs/product-discovery.md`; assert it states: web-first temporary transfers, Android kept, no new Windows/Linux desktop app, offline **already downloaded** only, new authorizations/recovery/transfers online, browsers trusted only if independently verified, package + trusted device only, and D-008 retention not transfer TTL. Assert existing D-006/D-008/D-009 headings remain.
- [ ] **Step 2: Run RED** from worktree: `node --test test/issue-65-web-policy-record.test.js`; expected **FAIL because D-011 is absent**.
- [ ] **Step 3: Append D-011**, dated 2026-10-19 with `[DECIDED]` status, exact owner policy and trust consequences. Explicitly note the web-specific offline restriction supersedes the broader D-006 *default for new web Zero-Knowledge flows*, without erasing original records or claiming that legacy sync has already changed. Explicitly preserve D-008 and D-009; no final transfer TTL chosen.
- [ ] **Step 4: Run GREEN**: `node --test test/issue-65-web-policy-record.test.js`; expected **0 failures**. Diff-review only the decision record and its test. Commit together as one documentation/contract task with the verified configured author identity, only after this plan is approved.

## Task 2: Establish browser capability and key-custody evidence without enrollment

**Files**
- Create: `test/support/issue-65-web-capability-evidence.js`.
- Create: `test/issue-65-web-capability-evidence.test.js`.
- Create: `test/support/issue-65-web-local-probe.html`.
- Create/append: `docs/validation/2026-10-19-rootark-web-phase-a-evidence.md`.

**Interfaces**
- Consumes: D-011; spec §4–5; exact client/browser capabilities discovered during the probe.
- Produces: `assessWebRecoveryEvidence(record)` → `{status: "UNVERIFIED" | "CANDIDATE_FOR_INDEPENDENT_REVIEW", reasons: string[]}` for **test-only evidence**. It must **never** produce `ELIGIBLE`, `APPROVED`, `freshnessProven: true`, or production trusted-device tokens.
- Evidence record fields: `{browserVersion, osVersion, originKind, prfObserved, userVerificationObserved, credentialSyncBehavior, privateKeyWrappingObserved, keyCopyOrRestoreTested, originDeliveryReviewed, independentReviewerVerified, measuredAt}`, with actual unknowns represented as `"UNKNOWN"` rather than truthy guesses; include no raw PRF output, key, password, token, credential ID or authenticator assertion.

- [ ] **Step 1: Write RED tests** `unknownPrfNeverBecomesTrusted`, `syncedPasskeyDoesNotProveDeviceBoundCustody`, `restoredProfileAndDeletedCredentialDoNotClaimRecovery`, `knownPrfStillRequiresIndependentReview`, and `evidenceObjectRejectsSensitiveFields`. Fixtures cover `UNKNOWN`, `false`, profile loss, copied credentials and apparently working PRF. Assert no result claims actual trusted status.
- [ ] **Step 2: Run RED**: `node --test test/issue-65-web-capability-evidence.test.js`; expected **FAIL** due missing evaluator.
- [ ] **Step 3: Implement exactly the narrow `assessWebRecoveryEvidence(record)` helper**, rejecting unexpected fields/prototypes and unsafe evidence blobs, preserving unknowns; no browser enrollment, no persistent secret state, and no auto-approval based on feature flags.
- [ ] **Step 4: Build an optional disposable local HTML probe**, only for manually initiated capability observations. Probe must run under an appropriate test secure context, use a local origin, present a clear explicit gesture before any WebAuthn operation, never create/delete a real account credential or write secret output, and record only sanitized browser/version/platform/support observations. A reported PRF property is **not** proof of actual PRF success; credential creation or auth tests need separate user consent, authenticator availability, and protocol review. If secure origin/browser/authenticator is missing, return `NOT_RUN` / `UNVERIFIED`, not `UNSUPPORTED` as universal product truth.
- [ ] **Step 5: Run GREEN**: `node --test test/issue-65-web-capability-evidence.test.js`; expected **0 failures**. Record precise environment, explicit test dates and `NOT_RUN` evidence when no real browser is available. Do **not** install Playwright or substitute a headless mock for a real hardware/key-custody result. Commit only the helper/probe/tests and factual evidence.

## Task 3: Freeze online-only acceptance and inspect existing browser delivery

**Files**
- Create: `test/issue-65-web-offline-evidence.test.js`.
- Append: `docs/validation/2026-10-19-rootark-web-phase-a-evidence.md`.

**Interfaces**
- Consumes: D-011, `public/service-worker.js`, `public/client/rootark-offline-queue.js`, `public/client/rootark-protected-session.js`, and current `rootark-zk-recovery-history-v2.js` APIs.
- Produces: a **non-production policy/compatibility evidence table**, not an enforcement adapter or signed admission ticket.

- [ ] **Step 1: Write RED tests** for `downloadedFileNotRevocable`, `offlineSensitiveOperationsBlockedInContract`, `legacyQueueNotNewZkAuthority`, `staleShellNotFreshSecurityState`, and `publicHistoryIsNotOnlineFreshness`. The first tests load the not-yet-created `test/fixtures/issue-65-web-offline-contract.json`; require exact cases `read-downloaded-copy=allow-user-copy`, `view-already-open-plaintext=already-held-only`, `new-transfer=block`, `resume-transfer=block`, `enroll-device=block`, `recover-package=block`, `browse-protected-index=block`, `legacy-queued-sync=not-authorized-for-zk`. Every blocked remote action has `requiresFreshAuthority=true`. Inspect the actual service-worker/queue source or simulate its existing functions in a disposable VM. Tests distinguish policy from existing runtime enforcement: **do not assert current code enforces an admission gate that does not exist**.
- [ ] **Step 2: Run RED**: `node --test test/issue-65-web-offline-evidence.test.js`; expected **FAIL** because the contract fixture does not exist yet. Do not fail the old application solely because it has an explicitly inventoried legacy queue.
- [ ] **Step 3: Create the exact test-only JSON policy fixture and supply evidence**: use `schema="rootark-web-offline-contract/v1"` and the actions/values in Step 1, with no code to authorize real requests. Record current service-worker shell-cache behavior, `/auth` and API cache exclusions, legacy encrypted-envelope queue replay possibilities, existing Web Crypto caller-key custody, and that a public verified history reports `freshnessProven=false`. Classify missing real CAS/status/witness admission as **BLOCKED**, not PASS.
- [ ] **Step 4: Run GREEN** on the documentation/evidence contracts: `node --test test/issue-65-web-offline-evidence.test.js`; expected **0 failures** for the accurately classified *test-only evidence*, not for unimplemented runtime safety. Add an explicit matrix separating **offline exported file**, **in-memory already-held content**, **new file transfer/download**, **new auth**, **package recovery**, and **offline legacy queued operation**.
- [ ] **Step 5: Commit** the test and evidence-document update only; do not edit `public/`, `server.js` or existing queues. In particular, never quietly drain the legacy queue to prove it safe.

## Task 4: Consolidate security evidence and hand off the next gates

**Files**
- Complete: `docs/validation/2026-10-19-rootark-web-phase-a-evidence.md`.

**Interfaces**
- Consumes: Task 1 policy record, Tasks 2–3 tests/probe evidence, existing Node library F-01/F-02 audit acceptance.
- Produces: status matrix and a recommendation for **one next separate design**; not permission to register browsers or deploy a service.

- [ ] **Step 1: Assemble an explicit claim matrix** with `PASS_TEST_ONLY`, `OBSERVED`, `NOT_RUN`, and `BLOCKED` statuses for policy, capability/PRF, key-storage/copy resistance, browser crypto suite, Argon2id Web worker, external witness, CAS/status authority, protected-content admission, transfer TTL, Android interoperability and end-to-end recovery. Link exact tests, environment, and SHA.
- [ ] **Step 2: Add a negative readiness test** `unverifiedWitnessAndKdfNeverCountAsReady` to `test/issue-65-web-capability-evidence.test.js`. Define a second **test-only** export `assessWebRecoveryIntegrationReadiness({browserEvidenceStatus, casStatus, witnessStatus, browserKdfStatus, keyCustodyStatus, cryptoInteropStatus})` → `{status: "BLOCKED_FOR_INTEGRATION" | "REQUIRES_SEPARATE_INTEGRATION_APPROVAL", reasons: string[]}`. With witness or browser KDF `NOT_RUN`, assert `BLOCKED_FOR_INTEGRATION`. Even when each field is independently reported `PASS`, the result may only be `REQUIRES_SEPARATE_INTEGRATION_APPROVAL`, **never** authorize enrollment. Run RED then GREEN for that exact regression and do not produce an approval token.
- [ ] **Step 3: Execute supported focused suite on Node 22** with temp/cache set exclusively to E:. On Windows use the verified `E:\servidor\.worktrees\.cache\node-v22.22.1-win-x64\node.exe` if still present and SHA/provenance are verified; on Ubuntu WSL use the verified Node 22.22.1. Run:
  `node --test test/issue-65-web-policy-record.test.js test/issue-65-web-capability-evidence.test.js test/issue-65-web-offline-evidence.test.js test/issue-65-recovery-history-v2.test.js test/issue-65-recovery-kdf.test.js`.
  Record the **actual** number of tests, passes, failures, and skips. On WSL Node 22 repeat the same focused list with `TMPDIR=/mnt/e/Chats/rootark-tests`; do not claim browser coverage from Node tests.
- [ ] **Step 4: Validate** `npm run validate:syntax`, `npm run validate:artifacts`, exact `git diff --check`, and verify no source/runtime/dependencies are modified. Run repository-wide tests/release gate only if appropriate for the change and within a separately managed non-destructive E: fixture; if not run or incomplete, label exactly that.
- [ ] **Step 5: Independent read-only security review** of exact code/doc SHA and all evidence. Record reviewer provenance only if backend/control-plane attests it; do not claim a native reviewer was used based on the model's text. Any failed test, real vulnerability, incorrect claim, missing matrix cell or surprise file blocks acceptance. Commit final documentation-only evidence correction if needed; no push/merge/deploy.

## Specification coverage and deliberate deferrals

| Approved specification area | First-phase coverage | Explicit gate |
|---|---|---|
| §1–3 platform/offline policy and existing repo facts | Task 1 D-011 and Task 3 source inventory | Does not migrate or remove legacy offline/CLI behavior |
| §4–5 browser threat model and eligibility | Task 2 matrix, local probe, Task 4 evidence | No browser is declared eligible; no approved key-custody backend or origin-integrity assurance |
| §6 user-downloaded offline content and online operations | Task 3 policy contract and read-only audit | No production network admission check; real witness absent |
| §7 recovery journeys | Task 2 records feasibility prerequisites | No UI/pairing/export implementation; UI-UX-PRO-MAX applied in separately approved UI phase |
| §8 CAS/status/witness trust | Task 4 blocks and interface handoff | Entirely separate Packet B specification, real cross-process proof required |
| §9 finite transfer lifecycle | Task 1 documents open TTL decision; Task 4 blocks | Separate Packet C owner decision and specification |
| §10–11 adversarial tests and staged gates | Tasks 2–4, exact SHA and honest omissions | Node/mock evidence never proves platform or infrastructure behavior |
| §12 remaining owner decisions | Task 4 lists and labels open choices | No default browsers, TTL, authority provider or migration inferred |

## Exit criteria / handoff

**This phase is complete only when** (a) D-011 accurately reflects user approval without rewriting past decisions, (b) available Node evidence tests pass on supported platforms, (c) observed browser results identify actual environment and no secrets are retained, (d) external witness, CAS, key-custody and browser interoperability remain visibly **blocked** until independently proved, (e) the evidence matrix is internally consistent, and (f) exact changed-file SHAs receive independent review.

If no browser/credential hardware is available, the phase may still close as **`EVIDENCE_BASELINE_COMPLETE — BROWSER_ELIGIBILITY_UNVERIFIED`**, but **must not** close as implementation of trusted web recovery or as browser eligibility approval.

**Never infer from this plan:** approval of a browser as a trusted device; permission to ship encrypted transfer flows; selecting PostgreSQL or any shared provider; real witness freshness; package activation in the browser; Android runtime acceptance; permission to change D-008 backup semantics; acceptance of issue #65; CI/full-release success, merge, push, or deployment.

**Next design proposal after this phase:** Packet B shared CAS/status/witness architecture for online admission **or** a focused browser key-custody feasibility decision, depending on which has verifiable prerequisite evidence. Both require separate user and independent security approval before implementation.

**Execution method for owner to choose at plan review:** Direct/native Codex execution with its existing primary implementer and one independently verifiable final security reviewer is preferred for this evidence-only scope. Native subagents are optional, not silently assumed; do not invoke Dual Agents/Dual Codex unless newly authorized. The owner must explicitly accept this plan before any task's product/test/document changes are executed.
