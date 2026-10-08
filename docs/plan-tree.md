# Root.ark Plan Tree

Last reconstructed: 2026-07-25 (historical baseline)
Last branch reconciliation: 2026-10-08

Repository: `bielxdh3/root.ark`

The latest recorded GitHub query in [the issue ledger](issue-ledger.md) is after PR #116 merged, at `Root/main` `fd995b2ae587140db8ea1ba9de62cf7557ee0516`. Push Security Regression, CodeQL, default-branch Dependency Review, and Pages passed on that exact SHA. The mission execution record reports the local release gate passed there as well, but its exact stdout was not retained in the repository. The issue and PR snapshot is time-scoped; re-query GitHub before relying on it after later repository changes.

The security-correction code and main-push CI work in PRs #101, #103, #114, #115, #99, #117, #118, and #116 are merged. Mission closure remains `[PARTIAL]`: the full browser matrix is incomplete, so complete UI acceptance is unproven. Whole restore is locally rollback-recoverable with durable provider reconciliation, not globally atomic. Issues #63–68 and #94, and incomplete PRs #95, #97, and #102, remain open as recorded in the issue ledger.

Historical canonical baseline HEAD at the 2026-10-01 reconciliation start: `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1` (`refs/heads/Root/main`). It is not the current default-branch SHA.

Historical reconstruction baseline retained for provenance: `4062f4c67bfda9d144aceb6dbbed539b8a917e4a` (2026-07-25).

## Historical live GitHub reconciliation — 2026-10-01

This dated section superseded older statements at the time it was written. Its issue, branch, and PR states are historical; use the current snapshot linked above for live state. Historical phase reports below retain their original dates and evidence boundaries.

- The live default branch was `Root/main` at `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1`. At that snapshot GitHub had seven open issues (#63–68 and #94) and one open PR (#95).
- Issue #83 is closed. Its sensitive-name policy remains active: `.env`, credential/service-account names, and private-key/certificate extensions remain excluded from backup content and quarantine payload references. PRs #86 and #90 contain its completion evidence.
- PR #96 is merged at `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1`; its exact-head CodeQL analysis, dependency review, Ubuntu validation, Windows validation, and GHAS scan passed. This does not authorize a release.
- Issue #94 is represented by PR #95, which remains open. Exact head `95d99e4a934384fcfa2101dfc210741cd791a3d1` passes CodeQL, Analyze JavaScript / TypeScript, dependency review, Ubuntu Node 22 full validation, and Windows Node 22 syntax/tests. The focused upload-security suite passes 26/26, and targeted independent reviews approve parser ordering and server-generated staging-path identity/cleanup. Production replica topology is still unknown; the in-memory limiter and local-disk staging need shared/edge enforcement or confirmed single-process deployment before #94 can close.
- Issue #63 is an approved future feature tracker, not implementation authorization. The protected-index primitive exists, but the UI does not populate it; FTS5 and advanced search remain deferred until the searchable corpus, encrypted-index lifecycle, privacy leakage, and acceptance criteria are defined.
- Issue #64 is a future Android-client tracker, not implementation authorization. There is no Android/Gradle project or Android CI. A native implementation remains gated on a separate architecture/threat-model and protocol-compatibility test plan.
- Issue #65 approves the Zero-Knowledge direction and bounded cryptographic foundation; it does not establish a Zero-Knowledge runtime. Current uploads and server-side operations can still expose plaintext. Migration inventory, client authorization, recovery authority, mixed-mode window, and exact-head runtime/backup acceptance remain open.
- Issue #66 is approved but not complete. PR #97 implements selected-path reconciliation, remote-only state, and guarded cache/materialization flows. Metadata-only remote listing and pagination, a Files On-Demand native provider/UI, and a portable guarantee that eviction cannot race an external writer with an open handle remain missing.
- Issue #67 is approved but not complete: existing backups and sync revisions are recovery prerequisites, not a ransomware shield. Burst detection, a recoverable pause/review barrier, protected per-object recovery history, and authorized restore are absent.
- Issue #68 is approved but not complete: existing public links are single-file bearer links with expiry/limits, not operation-scoped capabilities. Protected-link delivery remains gated on least-privilege capability enforcement and owner choices for link UX, expiry, and recipient recovery.

## Historical reconciliation work after the live baseline — 2026-10-01

This addendum records the published work after the live GitHub baseline above. PR #97 remains open and unmerged; PR #98 was merged into `Root/main` at `1df5e4640d4aea7dc700f2088059f489c2e51af0`. Neither PR changes issue state or marks an issue complete. PR #95 remains open after all exact-head checks passed because production replica topology is still unverified.

- Issue #64 has a native-client architecture and threat-model document only. No Android application, Gradle project, build, or CI exists.
- Issue #65 has a Zero-Knowledge migration contract and a read-only inventory prototype limited to explicitly selected fixture files under an operating-system temporary directory. The prototype reports recognized legacy encryption modes using run-scoped opaque references; it does not inspect live application storage or establish migration readiness. Its four focused tests pass. Runtime migration, authorization, recovery authority, mixed-mode window, backup/restore acceptance, and the remaining owner decisions are still open.
- Issue #66 has a selective-sync implementation in PR #97 at `a6a33a92cd6902f303254e60031da4bdc04cec04`, including selected-path tracking, remote-only state, move-out reconciliation, and guarded cache/materialization flows. The focused `test/phase16-sync-engine.test.js` run records 31 passing tests and one platform-skipped test. The current list API still transfers complete remote records including ciphertext before local path filtering, so network payload transfer is not selective. Exact-head CodeQL, Analyze JavaScript / TypeScript, dependency review, and Ubuntu/Windows CI pass; an independent targeted review of the move-out change found no actionable findings. There is no Windows Files On-Demand provider/UI, metadata-only catalog, or paginated remote listing, and portable open-handle quiescence for eviction is unresolved. PR #97 and the issue remain open.
- Issues #67 and #68 have architecture/acceptance contracts only. No runtime protection or capability-sharing feature is implemented; the owner choices recorded in those contracts remain unresolved.
- PR #98 merged the previous documentation reconciliation. This update records the later #95/#97 checks and open acceptance gates above.

## Status labels

- `[DONE]`: implemented and supported by relevant validation evidence.
- `[ACCEPTED-LOCAL]`: reviewed and accepted for the bounded local engineering scope; environment, production, or publication acceptance may remain open.
- `[IMPLEMENTED-UNVERIFIED]`: code/documentation exists, but operational or regression proof is incomplete.
- `[CURRENT]`: active phase. New execution should stay within this phase.
- `[NEXT]`: next approved phase after the current gate.
- `[PARALLEL-DISCOVERY]`: product questions may proceed without runtime implementation.
- `[LATER]`: valid future work after prerequisites.
- `[BLOCKED]`: must not start until named prerequisites are complete.
- `[DECISION REQUIRED]`: requires an explicit product or architecture decision.
- `[DO NOT IMPLEMENT YET]`: recorded idea, not approved execution work.

A feature is not `[DONE]` merely because files, routes, UI, or documentation exist. Completion requires relevant tests, disposable-data validation, or an explicit manual validation record.

## Source-of-truth order

1. Current code and tests on the actual branch.
2. `docs/issue-ledger.md` for the latest verified live GitHub issue, PR, and default-branch snapshot.
3. This plan tree for phase order and historical acceptance evidence.
4. Dedicated security, architecture, operations, and validation documents.
5. GitHub issues for executable scope.
6. Historical chat context only as input, never as proof.

The newest issue reconciliation snapshot is `docs/issue-ledger.md` (queried against GitHub on 2026-10-08 at source SHA `14428690bef7c02648fd0be9570aabb17ae6de1a`; point-in-time and superseded by later PR publication/merge). The canonical Phase 11 Issue #6 reconciliation remains historical evidence: `docs/roadmap/phase-11-backlog-reconciliation.md` records `PHASE_11_BACKLOG_RECONCILED` at the accepted Phase 10 starting SHA `76f2a02cf6e3872ab2d7b61ff617021daf893c61`.

Master Phase 0-16 ledger and independent local blocker taxonomy: `docs/issue-ledger.md`. The governing continuation supplies the original meanings for all phases; local statuses and evidence are reconciled there without converting design or historical evidence into acceptance.

## 0. Historical product snapshot

This product inventory was reconstructed before the 2026-10-07 live-state snapshot above. Treat its implementation labels as dated evidence rather than current release acceptance.

### Application identity

- `[IMPLEMENTED-UNVERIFIED]` Independent Node.js/Express file-management application currently exists in this repository.
- `[DECIDED]` D-001 keeps this repository actively developed as Root.ark while allowing only a future, explicitly designed and approved migration or selective reuse into BielOS. Track remaining relationship consequences in issue #10.
- `[DECISION REQUIRED]` Confirm final spelling and branding: `Root.ark`, `root.ark`, `root.arc`, or another approved name. Track in issue #4.
- `[RECONCILED — historical 2026-08-13]` At that local reconciliation, GitHub reported `Root/main` and `origin/HEAD` resolved to `28747c6ebdac873650e2d5a3c6193824e7cc9985`. That SHA is historical; the current default-branch SHA is recorded in `docs/issue-ledger.md`. The `codex/folders-acl` references remain historical provenance. Issue #14 was locally closure-ready at that time; remote issue closure was not claimed.

### Verified code-level capabilities

The following are present in code or project documentation, but several require operational validation:

- `[IMPLEMENTED-UNVERIFIED]` User login with bcrypt and JWT.
- `[IMPLEMENTED-UNVERIFIED]` Login rate limiting, progressive delay, IP/username blocking, generic errors, analytics, and audit events.
- `[IMPLEMENTED-UNVERIFIED]` Role and granular permission handling.
- `[IMPLEMENTED-UNVERIFIED]` Logical folders and file-level permissions.
- `[IMPLEMENTED-UNVERIFIED]` Simple and chunked upload flows with pending approval.
- `[IMPLEMENTED-UNVERIFIED]` File versions, expiration, previews, downloads, public links, and access limits.
- `[IMPLEMENTED-UNVERIFIED]` Encryption modes and encrypted-file metadata.
- `[IMPLEMENTED-UNVERIFIED]` Analytics, dashboard, audit logs, CSV export, and WebSocket refresh.
- `[IMPLEMENTED-UNVERIFIED]` Local, S3, and Google Drive storage compatibility.
- `[IMPLEMENTED-UNVERIFIED]` SQLite repositories and JSON-to-SQLite migration with legacy fallback.
- `[IMPLEMENTED-UNVERIFIED]` Backup, automatic backup, restore validation, and pre-restore backup.
- `[IMPLEMENTED-UNVERIFIED]` Trash for files and folders with restore and permanent deletion.
- `[IMPLEMENTED-UNVERIFIED]` Suspicious extension blocking, optional ClamAV integration, and quarantine.
- `[IMPLEMENTED-UNVERIFIED]` WebDAV MVP.
- `[IMPLEMENTED-UNVERIFIED]` One-way local-to-server synchronization CLI MVP.
- `[IMPLEMENTED-UNVERIFIED]` Partial modularization into repositories, services, routes, middleware, and database modules.

### Known architectural condition

- `[IMPLEMENTED-UNVERIFIED]` `server.js` remains the central integration file and is several thousand lines long.
- `[BLOCKED]` Broad modularization is blocked until critical security fixes and automated regression coverage exist. Track in issue #5.
- `[IMPLEMENTED-UNVERIFIED]` JSON and SQLite modes coexist; rollback flexibility exists, but behavioral parity and drift require proof.
- `[IMPLEMENTED-UNVERIFIED]` The main README does not accurately describe the current product surface.

## 1. Governance recovery

### Phase 1.0: Repository control layer

- `[CURRENT]` Create a short root `AGENTS.md` defining scope, safety, token economy, reasoning, validation, Git, and output rules. Issue #8.
- `[CURRENT]` Create this `docs/plan-tree.md` as the phase source of truth. Issue #8.
- `[CURRENT]` Create `docs/codex-workflow.md` with planner, executor, reviewer, and orchestrator boundaries. Issues #8 and #12.
- `[CURRENT]` Create `docs/product-discovery.md` for explicit future product decisions. Issues #4 and #8.
- `[CURRENT]` Create an initial code-backed security findings record. Issue #11.
- `[NEXT]` Open and review the governance PR.
- `[NEXT]` Merge only after confirming the documents do not claim unverified runtime behavior as completed.
- `[NEXT]` Close issue #8 after the governance PR merges.

### Phase 1.1: Release discipline

- `[NEXT]` Require one coherent goal per branch and PR. Issue #12.
- `[NEXT]` Require starting/final SHA, changed files, validations, unvalidated items, and remaining limitations in completion reports.
- `[NEXT]` Require plan-tree updates only after evidence.
- `[NEXT]` Prohibit force-pushes, history rewrites, and accidental removal of newer user work.
- `[NEXT]` Record CI status for the exact final SHA once CI exists.

## 2. Security stabilization

No new product feature should begin before the minimum security gate in phases 2.0 through 2.3 is completed.

### Phase 2.0: Bounded security inventory

Issue: #11

- `[NEXT]` Confirm the exact current code paths for the known findings below.
- `[NEXT]` Inspect only adjacent auth, realtime, and rendering helpers for equivalent defects.
- `[NEXT]` Assign severity, preconditions, impact, remediation issue, and validation requirement.
- `[NEXT]` Do not change runtime code during the inventory.
- `[NEXT]` Update `docs/security/current-findings.md` with confirmed evidence.

Known starting findings:

- hard-coded fallback for `JWT_SECRET`;
- bearer token and permission metadata in browser `localStorage`;
- user-controlled dashboard event text rendered through `innerHTML`;
- JWT passed in the WebSocket URL query string;
- role and permission claims embedded for an eight-hour token lifetime;
- no confirmed functional 2FA despite the QR dependency;
- dependency and regression-test baseline incomplete.

### Phase 2.1: Critical configuration and XSS fixes

Issue: #1

Prerequisite: phase 2.0 inventory confirms exact surfaces.

- `[DONE]` Remove the hard-coded JWT secret fallback and replace dashboard user-controlled activity/error rendering with text DOM nodes; startup, login/dashboard, adjacent-surface, and malicious-payload browser evidence are recorded.
- `[DONE]` Fail startup safely when a required production secret is absent or unacceptably weak; the disposable startup acceptance harness verifies non-zero exit and sanitized configuration output for missing and weak secrets.
- `[DONE]` Preserve a safe local-development setup with an ignored `.env` pattern, trackable invalid-placeholder template, and explicit process-environment startup instructions using a fresh Node `crypto` secret.
- `[DONE]` Replace unsafe dashboard activity rendering with DOM/text rendering; the real analytics-to-dashboard malicious-payload browser proof confirms literal rendering and no execution.
- `[DONE]` Review only directly adjacent changed dashboard surfaces for equivalent injection sinks.
- `[DONE]` Add focused startup and rendering regression tests; rendering, session-bootstrap, direct startup acceptance, and malicious-payload browser validation are recorded.
- `[DONE]` Verify login and dashboard behavior after the fixes with the recorded disposable browser validation.

Completion evidence:

- missing/unsafe production secret prevents startup;
- explicit safe configuration starts correctly;
- malicious event fields display as text;
- no real secret is committed or logged;
- relevant tests or manual validation are recorded.

### Phase 2.2: Session, token transport, and authorization freshness

Issue: #2

Prerequisites: phase 2.1 complete and initial auth tests available.

- `[DONE]` Stop placing JWTs in WebSocket query strings; cookie-authenticated upgrades validate Origin and the current session user before events are sent. Focused checks and recorded disposable browser/WebSocket validation passed.
- `[DONE]` Design and implement one bounded cookie-authenticated WebSocket handshake.
- `[DONE]` Revalidate the current user and permissions on the server rather than trusting stale permission claims for the full token lifetime. Every authenticated HTTP request reloads the active identity and derives current permissions; active WebSockets recheck expiry, current identity, disabled state, and `sessionVersion` before the next authenticated message or send. The Phase 2.2 closure audit reconciled the representative permission-removal and expiry regressions.
- `[DONE]` Implement token/session revocation or versioning for password, role, permission, disable, and deletion changes. The shared `PUT /users/:username` decision increments persisted `sessionVersion`; JSON preserves a Git-ignored per-username generation ledger across restart, and SQLite retains/increments a soft-deleted row generation atomically on recreation. Old HTTP and active-WebSocket credentials remain revoked.
- `[DONE]` Browser sessions use secure HttpOnly cookies (`SameSite=Lax`) with CSRF checks for cookie-authenticated writes; the transport decision and browser-session threat model are documented in `docs/security/browser-session-threat-model.md`. Issue #2 is ready to close after the Phase 2.2 closure-audit PR merges.
- `[DONE]` Add representative tests for disabled users, removed permissions, expiry, revocation, and realtime authentication. `test/auth-security.test.js` proves permission removal, JWT expiry, JSON delete/recreate rejection of old HTTP and active-WebSocket sessions, and new-session success; `test/users-repository.test.js` proves repeated SQLite recreation advances generation. Shared update-path analysis establishes the same protection for password, role, permissions, and disabled-state changes without redundant per-field integration tests.

Completion evidence:

- no bearer token in realtime URLs;
- removed access stops within the approved bound;
- disabled/deleted users cannot retain indefinite access;
- existing authorized HTTP and realtime behavior still works.

Closure audit: `docs/security/phase-2-2-closure-audit.md` reconciles source, regressions, merged PRs #17/#19/#20/#21/#22/#23, and successful `Security Regression` runs through #23 (`30650435892`). Issue #2 is ready to close after this documentation-only audit PR merges.

### Phase 2.3: Engineering and dependency baseline

Issue: #3

- `[DONE]` Add repeatable `test` and static-validation scripts. A clean checkout runs `npm ci` then `npm run validate`; reusable package scripts perform complete first-party JavaScript syntax validation, `npm test`, and the locked high-severity dependency audit. CI invokes the same scripts in separate steps.
- `[DONE]` Establish one meaningful vertical slice of automated security regression tests; eight focused tests now cover session, browser-token, WebSocket, WebDAV, rendering, and Archiver compatibility boundaries.
- `[IMPLEMENTED-UNVERIFIED]` Add tests for authentication, authorization, path handling, upload safety, trash, and backup/restore boundaries in small steps; authentication, backup compatibility, disposable real-server simple-upload authorization, suspicious-extension quarantine, filename containment, file-trash lifecycle, and JSON-mode backup/restore coverage are covered. The backup regression proves representative `manageBackups` denial before archive/history/lock side effects, runtime-only JSON/upload inclusion, backup-recursion exclusion (`data/backups`), no absolute/traversal archive entry names, child runtime-root archive/history/restore confinement, module-checkout non-modification, binary download checksum equality, invalid-confirmation non-mutation, pre-restore backup, and a disposable JSON round trip; existing sensitive-path filters remain source-reviewed, while dedicated hostile/sensitive archive fixtures remain the next task. A focused SQLite test preserves a configured external database path. Cloud backup, scheduler behavior, retention pressure, hostile ZIP corpus expansion, and full production SQLite recovery remain unverified.
- `[IMPLEMENTED-UNVERIFIED]` Upgrade Multer and Express through compatibility-preserving changes; Express is upgraded and validated, while Multer remains a separate bounded follow-up.
- `[IMPLEMENTED-UNVERIFIED]` Review remaining dependencies in bounded groups rather than one mass upgrade; the current lockfile audit is clean, while continuing dependency review remains open.
- `[DONE]` Add GitHub Actions CI for clean install, syntax checks, automated tests, and dependency audit; `Security Regression` run `30600354792` succeeded against `666fcbe5aee30710b20a01e13b1a24c8c6313206`.
- `[DONE]` Ensure this validation baseline and CI never include or upload real databases, uploads, backups, quarantine contents, tokens, credentials, or generated runtime ledgers; tests use disposable fixtures only.

Completion evidence:

- clean checkout has a documented validation command;
- tests fail when protected behavior is intentionally broken;
- CI reports against the exact commit;
- dependency changes preserve existing behavior.

Next bounded issue #3 task: add focused hostile-archive restore fixtures that exercise the existing traversal, symlink, sensitive-entry, and checksum rejection paths without changing restore behavior.

### Phase 2.4: 2FA design and implementation

Issue: #9

Prerequisites: phases 2.1 through 2.3 and a product decision about 2FA scope.

- `[DONE]` Implement the bounded all-user-compatible TOTP mechanism in `src/services/totp.js` and `src/routes/auth.js`: authenticated enrollment/confirmation, RFC 6238 login challenge, recovery-code consumption, secure disable, and privileged reset.
- `[DONE]` Encrypt seeds with the existing application master-key boundary, hash recovery codes with scrypt, fail closed on missing/invalid key material, and avoid secret-bearing audit/response paths.
- `[DONE]` Preserve session-version revocation, cookie/CSRF checks, enrollment-only route fencing, realtime freshness, and JSON/SQLite user persistence through migration 5.
- `[DONE]` Add optional, role-required, and global-required policy modes without implicit all-user activation; default behavior for existing users remains optional/inactive.
- `[ACCEPTED-LOCAL]` `PHASE_10_TOTP_IMPLEMENTED_AND_SECURITY_REVIEW_APPROVED`: independent evidence records 52/52 focused auth/TOTP/security tests, 616/616 broad `npm.cmd test` in 38.2 seconds, syntax 88/88, runtime artifacts, `npm ci --dry-run`, `git diff --check`, targeted secret scan, and bounded disposable HTTP evidence passing. The subsequent fail-closed policy-configuration correction passed the broader auth/TOTP/security regression matrix at 51/51, including startup and dynamic HTTP/realtime invalid-configuration rejection. `npm audit` remains non-clean only for the pre-existing high `brace-expansion` advisory. The +301s→+600s future-iat change was test-only and production behavior was unchanged. Shared live policy re-evaluation, HKDF seed-key derivation, and no-store sensitive responses are covered. Browser automation, providers, production, remote CI, release, and publication acceptance remain open; see `docs/security/phase-10-totp.md`.

Phase 9 bounded foundation closeout: `PHASE_9_BOUNDED_FOUNDATION_ACCEPTED` for the reviewed `rootark-zk-1` foundation at the starting SHA, with local crypto vectors now passing after dependency installation. This does not accept zero-knowledge migration/runtime/release behavior. Residual Phase 9 handoffs remain dependency provenance/reproducibility, integration/runtime migration, provider/browser/CI/production evidence, and independent review.

### Phase 9 runtime protocol compatibility — Issue #65

- `[IN PROGRESS]` Add a separately versioned authorization-manifest profile for HPKE sender setup: v2 `info` binds every static core field before setup, `hpke_enc` is bound by the HPKE KEM context, and v2 AAD binds the digest of the complete core after setup. Preserve exact v1 group-wrap bytes and reject unsupported manifest versions.
- Acceptance requires deterministic v2 manifest/info/AAD vectors; public RFC 9180 context setup followed by AAD-dependent sealing/opening; signature, scope, expiry, and replay checks; v2 replay may be claimed only by the compound opener after HPKE authentication; a tampered HPKE ciphertext must not consume a replay ID; plaintext may be returned only after an atomic replay claim; unchanged v1 group-sharing behavior; independent crypto/security review; and exact-head CI. This local step does not claim full ZK runtime migration or release acceptance.

## 3. Operational validation of existing features

Issue: #7

Prerequisites: critical security fixes complete and disposable local workspace available.

### Phase 3.0: SQLite migration and persistence

- `[BLOCKED]` Run migrations in a disposable workspace.
- `[BLOCKED]` Run JSON-to-SQLite import twice and prove idempotence.
- `[BLOCKED]` Verify users, permissions, folders, links, versions, audit, analytics, pending uploads, and encrypted metadata.
- `[BLOCKED]` Restart and confirm persistence.
- `[BLOCKED]` Record JSON fallback and dual-write limitations.

### Phase 3.1: Backup and restore

- `[BLOCKED]` Create a disposable backup containing controlled metadata and files.
- `[BLOCKED]` Verify manifest, checksum, exclusion of secrets, and retention behavior.
- `[BLOCKED]` Execute a restore only against disposable data.
- `[BLOCKED]` Verify pre-restore backup and restart requirements.
- `[BLOCKED]` Test traversal, absolute-path, and symlink rejection with safe fixtures.

### Phase 3.2: Trash and file lifecycle

- `[BLOCKED]` Verify file and folder move to trash.
- `[BLOCKED]` Verify restore conflicts and metadata preservation.
- `[BLOCKED]` Verify permanent-delete authorization.
- `[BLOCKED]` Verify public links, preview, download, versions, and cloud references do not bypass trash state.
- `[BLOCKED]` Verify cleanup behavior and restart persistence.

### Phase 3.3: Upload scanning and quarantine

- `[BLOCKED]` Verify safe file upload.
- `[BLOCKED]` Verify suspicious extension handling.
- `[BLOCKED]` Verify quarantine invisibility and access denial.
- `[BLOCKED]` Verify ClamAV-unavailable fail-open/fail-closed behavior.
- `[BLOCKED]` Run live ClamAV validation only when the daemon is actually available.
- `[BLOCKED]` Verify simple, chunked, pending, preview, download, share, cloud-sync, and audit boundaries.

### Phase 3.4: WebDAV MVP

- `[BLOCKED]` Verify OPTIONS, PROPFIND, GET, HEAD, PUT, and MKCOL.
- `[BLOCKED]` Verify authorization and permission filtering.
- `[BLOCKED]` Verify expired, trashed, encrypted, version-internal, and unauthorized files remain hidden.
- `[BLOCKED]` Verify traversal rejection.
- `[BLOCKED]` Verify DELETE, MOVE, LOCK, and UNLOCK remain blocked as documented.
- `[BLOCKED]` Test an actual Windows mount where feasible.

### Phase 3.5: Synchronization MVP

- `[BLOCKED]` Verify initialization without saving passwords.
- `[BLOCKED]` Verify state, hash, mtime, and ignored-file handling.
- `[BLOCKED]` Verify new and changed uploads, pending approval, optional auto-approval, and token renewal.
- `[BLOCKED]` Verify the documented 8 MB limit.
- `[BLOCKED]` Confirm that download, deletion sync, conflict resolution, background service, and bidirectional sync remain unsupported.

### Phase 3.6: Validation report

- `[BLOCKED]` Create a dated report under `docs/validation/`.
- `[BLOCKED]` Mark each claim passed, failed, blocked, or not tested.
- `[BLOCKED]` Convert confirmed defects into separate scoped issues.
- `[BLOCKED]` Do not repair unrelated defects opportunistically inside the validation run.

### Phase 3 status reconciliation (2026-08-13)

The committed Issue #7 report at `docs/validation/2026-08-02-operational-validation.md` is the current historical evidence for Phase 3: it records 21 `PASS`, 0 `FAIL`, and 2 environmental `BLOCKED` claims for live ClamAV and an actual OS WebDAV mount, with no product failure. The existing `[BLOCKED]` lines in Phases 3.0–3.6 are preserved as a derived reproduction checklist, not a claim that the validated historical run never occurred. A fresh rerun remains environment-dependent and is not claimed by this continuation.

## 4. Architecture stabilization

Issue: #5

Prerequisites: phases 2.1 through 2.3 complete and relevant tests covering each extraction target.

### Phase 4.0: Responsibility map

- `[DONE]` Map routes, repositories, services, persistence paths, and shared helpers in `docs/architecture/current-server-responsibility-map.md` at the current default SHA.
- `[DONE]` Identify concrete duplicated authorization, path, JSON/SQLite, audit, and storage logic with classifications and locations.
- `[DONE]` Define an evidence-backed extraction order and select realtime authentication/notifications as the first bounded candidate.
- `[DONE]` Complete the mapping task without moving runtime code.

### Phase 4.0.1: Realtime transport contract coverage

- `[DONE]` Add focused public-contract coverage for rejected upgrades, connected-first ordering, exact event envelopes, notification source/timestamps, message-rate reset, heartbeat/idle termination, and child-process shutdown cleanup in `test/realtime-transport-boundaries.test.js`.
- `[DONE]` Validate the focused realtime suite twice at 7/7, the auth-security suite at 13/13, and the combined auth/realtime run at 20/20; syntax and `git diff --check` also passed at local HEAD `28747c6ebdac873650e2d5a3c6193824e7cc9985`.
- `[IMPLEMENTED-UNVERIFIED]` Buffered-client close remains not directly covered because a deterministic public fixture would require brittle backpressure forcing or runtime changes; browser, CI, provider, and production behavior remain outside this phase.

### Phase 4.1: Bounded extractions

- `[DONE]` Extract the realtime transport and notification fan-out boundary into `src/realtime/server.js`; retain thin compatibility adapters in `server.js`, preserve the shared `parseBoundedNumber` helper used by WebDAV, and leave producer call sites and public contracts unchanged.
- `[DONE]` Validate the extracted working tree with realtime transport 7/7 twice, auth-security 13/13, realtime/WebDAV meta-remediation 62/62, combined realtime/auth 20/20, syntax checks, and `git diff --check` at local base `28747c6ebdac873650e2d5a3c6193824e7cc9985`.
- `[IMPLEMENTED-UNVERIFIED]` Buffered-client close is not directly covered; browser, CI, provider, production, and remote-closure behavior remain outside this local phase.
- `[DONE]` Add disposable upload-scanning contract coverage for ClamAV-unavailable fail-open, fail-closed quarantine, clean INSTREAM parsing, infected INSTREAM quarantine, suspicious extensions, and path containment in `test/upload-security.test.js`; the focused suite passed 16/16 twice locally.
- `[IMPLEMENTED-UNVERIFIED]` Live ClamAV daemon behavior, chunked/WebDAV/provider/production scan-entry parity, and zero-knowledge client-side scanning remain unverified or architecturally open.
- `[DONE]` Extract the current upload scanning/quarantine boundary into deliverable `src/upload-scanning.js`; preserve the thin `server.js` adapter, all three entry points, fail-open/fail-closed semantics, quarantine/audit contracts, and D-009's unverified-quarantine limitation.
- `[DONE]` Validate the extracted working tree with upload-security 16/16 twice, realtime transport 7/7, auth-security 13/13, realtime/WebDAV meta-remediation 62/62, syntax checks, and `git diff --check` at local base `28747c6ebdac873650e2d5a3c6193824e7cc9985`.
- `[DONE]` Validate the existing `services/cloudStorage.js` boundary with mock-only inventory contracts for S3/Drive prefix, parent, metadata, and duplicate-identity containment; `test/cloud-storage.test.js` passed 27/27 twice without provider credentials.
- `[IMPLEMENTED-UNVERIFIED]` No redundant cloud runtime extraction was made; external provider behavior and D-003/D-009 compatibility remain unverified.
- `[DONE]` Validate the existing direct-protocol WebDAV boundary with executable/oversize/abort, completed-journal recovery, crash-consistency, and meta-remediation suites (90/90 combined); no OS mount or runtime extraction was claimed.
- `[IMPLEMENTED-UNVERIFIED]` WebDAV remains inline because metadata journaling, cloud intent, and D-009 local-bridge requirements make a safe bounded extraction larger than this phase; mount/provider/production behavior remains gated.
- `[NEXT]` Execute the missing disposable JSON/SQLite parity, migration, and restart probes described in `docs/validation/2026-08-13-json-sqlite-parity-matrix.md`; native binding availability, full parity, and the final SQLite production policy remain environment- and owner-gated.
- `[BLOCKED]` Prefer existing partial boundaries rather than inventing a new framework.
- `[BLOCKED]` Preserve CommonJS, route names, response shapes, storage behavior, and UI contracts.
- `[BLOCKED]` Use one coherent commit per extraction.
- `[BLOCKED]` Compare behavior before and after with focused tests.

Potential extraction order after coverage exists:

1. realtime authentication and notifications;
2. upload scanning and quarantine;
3. cloud storage;
4. WebDAV;
5. file versions and lifecycle;
6. encryption;
7. remaining route families;
8. persistence-mode simplification.

### Phase 4.2: Persistence convergence

- `[DONE]` Validate focused SQLite recovery, migration-generation, trash-persistence, and archive/staging safety contracts: the disposable combined run passed 70/70 after rebuilding the native `better-sqlite3` binding.
- `[DONE]` Add the source-backed JSON/SQLite parity matrix at `docs/validation/2026-08-13-json-sqlite-parity-matrix.md`; it records the bounded 70/70 evidence and the remaining probes without claiming full parity.
- `[IMPLEMENTED-UNVERIFIED]` Targeted recovery/generation/transaction evidence does not establish complete JSON/SQLite parity, migration/restart coverage across every entity, or long-running production migration safety.
- `[DECISION REQUIRED]` Decide whether SQLite becomes mandatory for production; the parity matrix recommends it only after parity and migration acceptance and owner approval.
- `[DONE]` Record bounded migration, rollback, restart, and production-policy limitations in the JSON/SQLite parity matrix; implementation and full parity remain open.
- `[BLOCKED]` Remove legacy paths only after data migration and rollback strategy are proven.

## 5. Product discovery track

Issues: #4 and #10

This track may proceed conversationally in parallel with stabilization. Runtime implementation remains blocked until decisions are recorded and approved.

### Phase 5.0: Product identity and repository relationship

- `[PARALLEL-DISCOVERY]` Final product name and branding.
- `[DECIDED]` D-001 keeps Root.ark active in this repository; future migration or selective reuse into BielOS requires a dedicated architecture, security, and contract phase.
- `[DECIDED]` Root.ark runtime, data, sessions, and authentication remain independent until an explicit integration is designed and approved.
- `[DONE]` Document the current independent Root.ark/BielOS boundary in `docs/architecture/rootark-bielos-relationship-contract.md`; Issue #10 is closure-ready locally, while future integration, migration, identity, and key relationships remain owner-dependent and the remote issue was not changed.
- `[PARALLEL-DISCOVERY]` Existing features to preserve, redesign, or retire.

### Phase 5.1: Users and trust model

- `[DECIDED]` Private administrator-controlled storage and transfer service; accounts, compartments, and access are created or approved by an administrator, with no normal public registration.
- `[DECIDED]` Unrelated users may coexist only in rigorously isolated compartments; external links or keys do not create normal users.
- `[DECIDED]` D-004 defines bounded administrator powers, explicit time-limited audited support impersonation, and minimum metadata visibility without plaintext access.
- `[DECIDED]` D-003 selects client-side zero-knowledge protection for user content; the server and administrator do not normally receive plaintext.
- `[DECIDED]` D-005 defines direct administrator account creation, revocable expiring invitations, user-controlled recovery, default retention, and audited permanent deletion.
- `[DECIDED]` D-006 defines trusted-device and recovery-package authorization, compartment-isolated keys, future-content rotation, and authorized offline access.
- `[DECIDED]` Public account registration is not part of the approved model; isolated request or sharing surfaces require separate design and approval.

### Phase 5.2: File and storage behavior

- `[DECIDED]` Backups may preserve encrypted blobs and required metadata, but must not create an administrator plaintext-recovery path.
- `[DECIDED]` D-006 requires client-side key generation, compartment-isolated key sets, rotation for new content after access loss, and protected offline material on authorized devices.
- `[DECIDED]` D-007 requires per-file keys, isolated compartment hierarchies, mandatory recovery-package verification, explicit historical re-encryption, and future-authorization rotation after package compromise; the frozen Phase 8 technical profile records the accepted implementation parameters, while executable proof and product policy remain separate.
- `[DECIDED]` D-008 sets 30-day normal deletion and backup retention, immediate access revocation, and backup-aware cryptographic erasure that cannot be declared complete while service-controlled decryption material remains usable.
- `[DECIDED]` D-009 requires encrypted client-generated previews and indexes, server-blind sharing, local-bridge-only zero-knowledge WebDAV, and eventual mandatory bidirectional synchronization; the accepted architecture/migration contract is documented, while Phase 9 implementation and acceptance remain separate.
- `[DONE]` Record the accepted zero-knowledge architecture and migration contract at `docs/architecture/zero-knowledge-migration-contract.md`; the bounded Phase 9 foundation closeout is recorded below and full zero-knowledge migration remains separate.
- `[DONE]` Complete the independent Phase 8 security closure in `docs/validation/2026-08-14-rootark-phase8-independent-security-closure.md`; the verdict is `PHASE_8_ACCEPTED_FOR_BOUNDED_PHASE_9_FOUNDATION`, with the exact HPKE tuple, sender manifest, deterministic encoding, one-shot wrap construction, candidate policy, and residual risks frozen.
- `[DONE]` Close the bounded Phase 9 foundation as `PHASE_9_BOUNDED_FOUNDATION_ACCEPTED`: the reviewed `rootark-zk-1` implementation and vectors pass locally after reproducible dependency installation; full zero-knowledge migration/runtime/provider/browser/CI/production/release acceptance remains open.
- `[DECISION REQUIRED]` Resolve only the genuine owner decisions: sharing/public-link UX, recovery authority, migration window/UX, and sync conflict UX. Primitive, envelope, nonce, library, vector, parser, and bounded 2FA policy choices are recorded technical/security decisions.
- `[IMPLEMENTED-UNVERIFIED]` Current server-readable encryption, metadata, previews/search, ClamAV, server-native WebDAV, sync MVP, and backup behavior remain legacy/current behavior and are not a claim that Root.ark is zero-knowledge today.
- `[PARALLEL-DISCOVERY]` Local, S3, Google Drive, or hybrid canonical storage.
- `[PARALLEL-DISCOVERY]` Approval workflow and intended purpose.
- `[PARALLEL-DISCOVERY]` Define the remaining sharing recipient, public-link, expiration, and limit details under D-009.
- `[PARALLEL-DISCOVERY]` Define the remaining version, restore, backup-key invalidation, and permanent-deletion mechanics under D-008.
- `[PARALLEL-DISCOVERY]` Define the remaining synchronization, conflict, offline, local-bridge, desktop, mobile, and PWA architecture under D-009.

### Phase 5.3: Privacy and operations

- `[DECIDED]` D-004 permits auditable security and operational logs with actor, IP, device, time, and action, without content, keys, decrypted names, or unnecessary sensitive data.
- `[DECIDED]` D-005 separates immediate access revocation from retained permanent deletion and requires reinforced confirmation for immediate destruction.
- `[DECIDED]` D-008 sets 30-day operational logs, 180-day security/audit logs, immediate access revocation, and truthful pending/completed states for backup-aware cryptographic erasure; detailed access, export, deletion, and privacy rules remain `[OPEN]`.
- `[DECIDED]` D-009 requires quarantine for unverified external uploads and preserves the zero-knowledge boundary for scanning, derived data, sharing, WebDAV, synchronization, and restore.
- `[DONE]` Public-link audit events correlate a link with a one-way SHA-256 token digest and do not persist the bearer token; route-level regression coverage is in `test/public-share-audit-security.test.js`. This closes the audit-secret exposure only; Issue #68 capability and zero-knowledge acceptance remains open.
- `[PARALLEL-DISCOVERY]` Define the remaining audit access, export, deletion, privacy, investigation-extension, quarantine, and operational ownership details.
- `[PARALLEL-DISCOVERY]` Data export and portability.
- `[PARALLEL-DISCOVERY]` Operational ownership, deployment, updates, and recovery.
- `[PARALLEL-DISCOVERY]` Features explicitly rejected or deferred.

### Phase 5.4: Approved product brief

- `[DONE]` Record approved Round 1 decisions D-001 through D-003 with consequences and follow-up dependencies; keep Issue #4 open.
- `[DONE]` Record approved Round 2 decisions D-004 through D-006 with consequences and explicitly open deferred details; keep Issue #4 open, while Issue #10's independent relationship is closure-ready locally and future integration remains owner-dependent.
- `[DONE]` Record approved Round 3 decisions D-007 through D-009 with consequences and explicitly open expert architecture and implementation details; keep Issue #4 open, while Issue #10's independent relationship is closure-ready locally and future integration remains owner-dependent.
- `[DONE]` Add `docs/architecture/rootark-bielos-relationship-contract.md` and `docs/architecture/zero-knowledge-migration-contract.md` for the high-risk relationship and zero-knowledge boundaries; these are architecture/threat-model deliverables, not runtime implementation or product acceptance.
- `[DONE]` Synchronize this plan tree with the accepted relationship, zero-knowledge, and parity documents while preserving owner-dependent choices, current implementation limitations, and no-remote-closure language.
- `[BLOCKED]` Do not silently reinterpret old implementation as the final product contract.

## 6. Feature backlog

Issue: #6

All items below are candidates, not commitments.

### Phase 11 backlog reconciliation — 2026-08-16

- `[ACCEPTED-LOCAL]` `PHASE_11_BACKLOG_RECONCILED` is recorded in `docs/roadmap/phase-11-backlog-reconciliation.md` for the exact accepted Phase 10 starting SHA `76f2a02cf6e3872ab2d7b61ff617021daf893c61`.
- `[DO NOT IMPLEMENT YET]` The canonical nine-item matrix maps current evidence, status, prerequisites, security boundaries, owner decisions, implementation boundaries, acceptance, validation, dependencies, and the required separate future issue for every candidate.
- `[DO NOT IMPLEMENT YET]` TOTP is reconciled to accepted Phase 10; bidirectional sync and WebDAV mutations target Phase 12; search, previews, PWA/clients, groups, and admin UX target Phase 13; deployment prerequisites target Phase 14; naming and branding remain an owner/product decision.
- `[HISTORICAL SCOPE]` No Phase 12+ source, test, migration, UI, dependency, synchronization, WebDAV, deployment, or product implementation was authorized by that reconciliation turn; later phase-specific authorizations and evidence are recorded below.

### Phase 12: ZK sync and local WebDAV bridge — 2026-08-16

- `[ACCEPTED-LOCAL]` Add the versioned client protocol with stable IDs, deterministic allow-listed metadata, AES-256-GCM/AAD envelopes, key epoch/compartment/device context, Lamport revisions, create/update/move/delete tombstones, and base-revision conflict semantics.
- `[ACCEPTED-LOCAL]` Add an atomic durable pending/seen journal with restart recovery.
- `[ACCEPTED-LOCAL]` Add the loopback-only bearer-protected local WebDAV bridge with containment/symlink/traversal checks, safe PROPFIND/GET/PUT/MKCOL/MOVE/DELETE, journal callbacks, and DELETE-to-trash behavior.
- `[ACCEPTED-LOCAL]` Add the authenticated, bounded, opaque `/sync/v1/objects` routes, including DELETE tombstone persistence, with per-user authorization, atomic persistence, conflict/replay/stale rejection, and no decryption/key handling; existing public WebDAV routes remain unchanged.
- `[ACCEPTED-LOCAL]` Record the independent 65/65 Phase 12 focused gate; the local executable slice passes 4/4. Broader dependency/provider/browser/production validation remains separate.
- `[BLOCKED]` Provider/browser/production validation, deployment hardening, release acceptance, and remote/owner review remain external to this local implementation.

### Phase 14: Deployment/adapters/resilience — 2026-08-16

- `[IMPLEMENTED-UNVERIFIED]` Add standard-library `/health` and fail-closed `/ready` adapters for JWT, explicit TOTP policy, master-key, and provider-critical configuration; responses are unauthenticated and sanitized.
- `[IMPLEMENTED-UNVERIFIED]` Normalize provider errors, cap retry/backoff and cancellation, provide idempotency helpers, and redact secret-bearing log/metric values.
- `[IMPLEMENTED-UNVERIFIED]` Attest protected sync records during sync-store restart, backup creation, and restore archive validation without decrypting ciphertext or accepting plaintext/key fields; preserve backup, trash, version, and route contracts.
- `[IMPLEMENTED-UNVERIFIED]` Focused failure-mode coverage is recorded in `test/phase14-deployment-resilience.test.js`; provider, dependency, native-binding, TLS, production, remote CI, and release gates remain open.

### Phase 15: Local release gate — 2026-08-16

- `[ACCEPTED-LOCAL]` Add `scripts/validate-release-gate.js` and preserve the exact Phase 14 starting SHA `bcf0861e3c6987331228816cb479ade525b3b555`.
- `[ACCEPTED-LOCAL]` Repair only the transitive `brace-expansion` lock resolution from 5.0.8 to the reviewed 5.0.9 registry tarball and integrity; package manifest parity and audit threshold remain unchanged.
- `[ACCEPTED-LOCAL]` The controlled pre-commit matrix records 13 passed, 0 failed, and 1 expected clean-worktree block. It covers lock/provenance, syntax, artifacts, diff, secret-material patterns, Phase 9 crypto, Phase 10 auth/TOTP, Phase 12 sync/WebDAV, Phase 13 client/groups, Phase 14 readiness/attestation, backup/restore, high-severity audit, and ciphertext-only evidence.
- `[BLOCKED]` Provider credentials/interoperability, browser/device behavior, live production/TLS/rollback, remote CI for the final commit, product approval, publication, and independent Phase 16 review remain external gates.

### Phase 16: Final security/quality review — 2026-08-16

- `[ACCEPTED-LOCAL]` Protocol v2 metadata AAD/schema enforcement, recoverable WebDAV overwrite journaling, bidirectional encrypted sync, strict client/offline boundaries, protected index/preview identity binding, and approved `rootark-zk-1` opaque group wraps are implemented and locally reviewed.
- `[ACCEPTED-LOCAL]` The controlled final-head cross-phase matrix recorded 66/66 tests passed, with separate realtime transport 4/4 and upload-security 12/12 boundary runs; syntax validation recorded 116/116 passed. WebDAV PUT has a distinct durable mutation event and explicit protocol-v2 translation, and the browser protected store now has an in-memory session hook.
- `[BLOCKED]` Canonical full `npm test` was attempted but remains blocked by the unavailable `better-sqlite3` native binding in the disposable install; remote CI, browser/provider/live-production/TLS, owner approval, and release evidence remain external.
- `[RECONCILED — 2026-10-06]` The previously unnamed Draft-PR statement cannot be mapped to a current live PR. PR #96 is merged; PR #95 remains open with its current CodeQL and Security Regression checks passing, while Issue #94's multi-process/replica enforcement gate remains unresolved. Merge state is not release authorization; no Phase 17 item is created or inferred.

### Authentication and administration

- `[ACCEPTED-LOCAL]` 2FA/TOTP Issue #9 is implemented and security-reviewed within the bounded local scope; final independent evidence is 52/52 focused and 616/616 broad tests, with remote/publication/release acceptance remaining separate.
- `[DO NOT IMPLEMENT YET]` Recovery and session-management UI.
- `[ACCEPTED-LOCAL]` Phase 13 adds authenticated group CRUD/membership with an atomic JSON store; `manageUsers` is required and folder `groupIds` add membership access without changing individual sharing.

### Search and previews

- `[DO NOT IMPLEMENT YET]` SQLite FTS5 content indexing.
- `[DO NOT IMPLEMENT YET]` Advanced filters.
- `[ACCEPTED-LOCAL]` Protected client index and preview services use browser AES-256-GCM and local decrypt-before-search/render; server search/preview behavior remains unchanged.
- `[DO NOT IMPLEMENT YET]` Thumbnail generation and lifecycle.

### Clients and protocols

- `[ACCEPTED-LOCAL]` Installable public-shell PWA, service-worker cache exclusions, encrypted client-local offline queue boundary, and opaque Phase 12 browser protocol adapter are present.
- `[ACCEPTED-LOCAL]` Bidirectional encrypted synchronization is implemented by the protocol-v2 `SyncEngine`; provider/browser/production acceptance remains external.
- `[ACCEPTED-LOCAL]` Deterministic remote-wins conflict handling, tombstones, retry, and deletion sync are covered by focused engine tests.
- `[ACCEPTED-LOCAL]` The protocol-v2 `sync:start` entrypoint runs the bidirectional engine; the legacy uploader requires an explicit development-only opt-in.
- `[ACCEPTED-LOCAL]` WebDAV PUT/MOVE/DELETE mutation events translate into strict protocol-v2 journal operations with trash/rollback protection.
- `[DO NOT IMPLEMENT YET]` Mobile client or mobile-specific strategy.

### Product and interface

- `[DO NOT IMPLEMENT YET]` Final rename and branding migration.
- `[ACCEPTED-LOCAL]` Minimal groups admin section and protected-search/offline status panel are wired into the existing UI; no redesign was performed.
- `[DO NOT IMPLEMENT YET]` New product features proposed casually in chat without discovery and issue creation.

## 7. Documentation and release readiness

### Phase 7.0: Documentation synchronization

- `[LATER]` Rewrite README to match the actual stack and capabilities.
- `[LATER]` Add safe setup and environment-variable documentation.
- `[LATER]` Link backup, migration, trash, WebDAV, sync, scanning, and security documents.
- `[LATER]` Clearly label MVP limitations and unvalidated claims.
- `[LATER]` Remove references to dependencies or architecture that no longer exist.

### Phase 7.1: Release gate

- `[ACCEPTED]` Phase 8 independent security verdict is `PHASE_8_ACCEPTED_FOR_BOUNDED_PHASE_9_FOUNDATION`; the bounded Phase 9 foundation is now `PHASE_9_BOUNDED_FOUNDATION_ACCEPTED`, while Phase 15 remains `RELEASE_GATE_BLOCKED_ENVIRONMENT`.
- `[BLOCKED]` Critical security findings closed or explicitly accepted.
- `[BLOCKED]` Repeatable tests and CI pass for the exact release SHA.
- `[BLOCKED]` Disposable operational validation completed.
- `[BLOCKED]` Backup and restore procedure proven.
- `[BLOCKED]` Secrets and generated data excluded.
- `[BLOCKED]` Deployment exposure and TLS/reverse-proxy configuration documented and verified.
- `[BLOCKED]` Product trust model and intended audience explicitly approved.
- `[BLOCKED]` Known limitations published honestly.

## 8. Immediate execution order

Historical completed checkpoints, retained as evidence rather than future work: Issues #11, #1, #2, #3, and #7 are closed/completed in the live repository state.

1. `[NEXT]` Measure JSON/SQLite parity and migration/restart behavior with disposable fixtures; native binding availability and final SQLite production policy remain open.
2. `[PARALLEL-DISCOVERY]` Continue structured product discovery; Rounds 1 through 3 are recorded, Issue #4 remains open, and Issue #10's current independent relationship is closure-ready locally while future integration remains owner-dependent; the remote issue was not changed.
3. `[BLOCKED]` Approve individual future features only after stabilization and discovery. Issue #6 is reconciled locally, but every candidate remains gated by its prerequisites, owner decisions, and a separate approved issue; Issue #9 remains separately gated.

## 9. Plan-tree update rule

When completing a task:

1. verify the actual final commit and branch;
2. record the exact validations performed;
3. distinguish passed, failed, blocked, and not run;
4. update only the affected plan-tree items;
5. do not erase historical limitations;
6. link the PR, issue, validation report, or architecture decision;
7. select the next item based on remaining risk, not novelty;
8. stop instead of inventing filler phases.
