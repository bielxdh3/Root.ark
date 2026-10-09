# Root.ark closure validation — 2026-10-08

## Closure snapshot used for the documentation follow-up — after PR #127

Queried live on 2026-10-08 after PR #127 merged. `Root/main` was `25e50cbaa26062202d470330e93d7beb4575693a`; this snapshot is time-scoped and the final post-documentation merge SHA must be queried and validated separately.

### Exact main validation at this snapshot

- Security Regression push [run #37787160598](https://github.com/bielxdh3/Root.ark/actions/runs/37787160598): Ubuntu Node 22 ran 987 tests (976 passed, 11 skipped, 0 failed); Windows Node 22 ran 987 tests (983 passed, 4 skipped, 0 failed). Syntax passed on both; Ubuntu passed runtime-artifact and configured high-severity dependency-audit checks.
- CodeQL [run #37787160551](https://github.com/bielxdh3/Root.ark/actions/runs/37787160551), default-branch Dependency Review [run #37787160662](https://github.com/bielxdh3/Root.ark/actions/runs/37787160662), and Pages [run #37787159434](https://github.com/bielxdh3/Root.ark/actions/runs/37787159434) passed on this SHA.
- `npm run validate:release-gate` passed on PR #127 candidate `2334bf0cd02125d316b3ff083cf784b3e9f82abb` with 21 passed, 0 blocked, and 0 failed. It has not yet run on exact merged SHA `25e50c…`.

### Live GitHub state at this snapshot

- PR #127 (`fix(restore): preserve provider inventory baseline`) merged from head `2334bf0cd02125d316b3ff083cf784b3e9f82abb` at `25e50cbaa26062202d470330e93d7beb4575693a`; its exact-head Analyze, Ubuntu, Windows, and CodeQL checks succeeded. The PR-only dependency-review job succeeded; the default-branch-only job was skipped on the PR event and later passed on the merged SHA.
- Open PRs #95 and #97 still target base `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1`; #95 is `DIRTY` and #97 `CLEAN`. Listed checks are from 2026-10-01, before this base. All 4 threads on #95 and all 5 on #97 are resolved. Their feature/security boundaries remain incomplete.
- Issues #63–68 and #94 remain open. The moderate Dependabot alert `GHSA-hp3w-g68c-fv3c` for `sprintf-js` remains open with no first patched version listed.

### Browser acceptance on disposable fixtures

A fresh Playwright session exercised a disposable runtime from PR #127 candidate `2334bf0…` on port `43781`, using temporary data, uploads, and quarantine directories. It did not use the user app on port `3215`. Verified flows include login and TOTP enrollment/challenge; folder creation; password-protected share creation and guest password access; server-key-encrypted synthetic upload and approval; 9 MiB chunk upload; trash, restore, and permanent deletion of synthetic items; manual backup, manifest inspection, restore confirmation/cancel, and a full restore on the disposable fixture followed by a server restart; group creation; direct ACL grant/revoke; rename/move; and version restore. Two chunk requests succeeded with HTTP 200; an intercepted first-chunk HTTP 500 appeared as an alert and created no pending row. A pending chunk upload was rejected successfully. Restoring v1 after creating v2 returned the file to 23 bytes and produced a successful `file.version.restore` audit record. The ACL grant used `PUT /file-access`, returned 200, and included a CSRF header; revocation also returned 200. The browser confirmed that restore-dialog Cancel returned focus to its still-connected opener and did not alter the backup table before the actual restore test.

At desktop 1280×800, tablet 768×1024, and mobile 390×844, document/body widths matched the viewport. Mobile navigation opened by keyboard Enter and closed with Escape, returning focus to the toggle. No horizontal overflow was measured. Audit CSV export downloaded `rootark-audit.csv`; `POST /audit/export` returned 200. The UI created group `acceptance-group` with member `user`. A synthetic file was renamed and moved; the move appeared in the root after refresh, though its response status was not captured. An overlength rename separately returned 400 and displayed the 30-character limit. Setting a synthetic item's expiration generated an audit event, but response status and actual expiry were not captured. The backup restore displayed success; after restarting only the fixture server, `/health` returned 200 and the restored data matched the pre-test state, with the test-created group absent. The admin UI showed no quarantined items; a later bounded pass confirmed only the empty quarantine state. A synthetic outsider account was created with `POST /users` 201 and a CSRF header; in a separate session, `GET /folders` returned only the root and `GET /list` returned zero files, so it could not see `AcceptanceFolder` or its file. During an unsaved create-folder dialog, the admin's typed value stayed present while the outsider uploaded a synthetic file (`POST /upload` 200 with CSRF); however, the pending count did not change and the upload did not appear, so no actual realtime refresh occurred and refresh-time dirty-form preservation remains unverified. The admin user table exposed account deletion but no session-revocation control, so session revocation was not tested. The expiration UI's shortest interval was one day, so actual expiry was not tested. A later bounded pass verified preview content and authenticated download; exact evidence is recorded below. No unexpected JavaScript exception was observed. Full browser acceptance therefore remains `PARTIAL`. Per-flow screenshots and a machine-readable trace were not retained.

A final bounded Playwright pass on the disposable fixture navigated top-level to the legacy approve and reject URLs; each returned 405 with `Allow: POST`, and the synthetic pending count stayed at one. An authenticated cross-origin `POST /folders` with `Origin: https://evil.invalid` and no CSRF header returned 403, and the probe folder was absent afterward. Preview of synthetic `share-me.txt` returned 200 and matched the fixture file's content hash; authenticated download used `POST /file-open-token` (200) followed by the one-time open-file request (200). `GET /quarantine` returned 200 and the admin UI showed the empty-state message; no quarantine fixture was created. The pass used only disposable fixtures, made no source changes, preserved its temporary artifacts, and stopped its test-owned server/helper processes.

The approved cleanup of the exact disposable fixture name `closure-ui-sample.txt` on the earlier test service at port `62376` was not performed: the deletion command was rejected by the tool safety boundary after the user authorized it. No alternate deletion route was used; current presence is unverified. The isolated browser runtime at port `43781` and user service at `3215` were not targeted for that cleanup.

### Restore semantics at this snapshot

PR #127 binds provider inventory markers and restore-sync queues to provider namespace and authenticated principal, validates provider context around inventory/commit/upload operations, and hardens legacy queue replacement. One unambiguous legacy queue can be rebuilt from a validated archived baseline; a durable supersession pointer retires the old queue after its lease and resumes after restart. Multiple ambiguous queues fail closed. Provider failure leaves durable retry state and cloud access blocked until reconciliation succeeds. Tests use fake providers and disposable fixtures; live S3/Google interoperability was not exercised.

Whole restore uses verified local preimages and compensating rollback/restart recovery for quarantine, JSON, uploads, SQLite files/sidecars, and restore-derived provider policy. It is not a globally atomic transaction. Migration failures after local commit retain a restart barrier and retry forward; previously committed migrations remain committed. External writers and cloud-provider state remain outside local rollback. Windows also lacks a portable directory-entry flush guarantee equivalent to POSIX. These are bounded residuals, not claims of full restore atomicity.

### Mission status at this snapshot

`PARTIAL`: exact-SHA CI is green on `25e50c…`, but the release gate on the merged SHA, complete browser acceptance, documentation merge, and fresh independent review remain pending. No claim of production readiness or end-to-end Zero-Knowledge is made.

## Superseded closure snapshot — after PR #124, before documentation follow-up

Queried live on 2026-10-08. `Root/main` was `ad4707037933ee9a65a53e76a26ae3b1cea01160`. This snapshot supersedes the historical status farther below, which reflects an earlier SHA. The documentation follow-up and its final-main validation were still pending at this snapshot.

### Exact main validation at this snapshot

- Security Regression push [run #37755424999](https://github.com/bielxdh3/Root.ark/actions/runs/37755424999): Ubuntu Node 22 ran 951 tests (940 passed, 11 skipped, 0 failed); Windows Node 22 ran 951 tests (947 passed, 4 skipped, 0 failed). Both passed syntax validation; Ubuntu also passed the runtime-artifact guard and locked dependency audit at the configured high-severity threshold.
- CodeQL [run #37755425122](https://github.com/bielxdh3/Root.ark/actions/runs/37755425122), default-branch Dependency Review [run #37755425085](https://github.com/bielxdh3/Root.ark/actions/runs/37755425085), and Pages [run #37755424791](https://github.com/bielxdh3/Root.ark/actions/runs/37755424791) passed.
- The local repository release gate had not yet been run on this exact SHA; a new run on the final merged SHA remains required. No PR-head result substitutes for that run.

### Live GitHub state at this snapshot

- PR #123 merged at `c41beeffc48de4f8261bd85168de921e4d43fe52`; PR #124 merged at `ad4707037933ee9a65a53e76a26ae3b1cea01160`.
- Open PRs: #95 and #97 only. Both remain based on `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1`; their latest listed successful checks are from 2026-10-01, not this base. PR #95 is `DIRTY`; #97 is `CLEAN`. All 4 review threads on #95 and all 5 on #97 are resolved.
- PR #102 is closed. PR #121 is merged at `e3e30c24d85784a4d07d61f4e7bd457ed5fc8395`.
- Issues #63–68 and #94 remain open. The moderate Dependabot alert `GHSA-hp3w-g68c-fv3c` for `sprintf-js` remains open with no first patched version listed.

### Browser and UI acceptance completed on disposable fixtures

A fresh real-browser acceptance pass used isolated local test runtimes and disposable accounts/files; it did not use the user app at `127.0.0.1:3215` or user data. The main matrix runtime on port `62390` loaded `server.js` from candidate commit `4cf73a0f0f3193cb68d6ddcd7bb0b16ec85755b4` through its temporary `launch.js`. That commit and `Root/main` `ad4707037933ee9a65a53e76a26ae3b1cea01160` have the identical Git tree `7a4ffac31b961e9184204a575a510146b877ec5d`, tying the tested application code to the exact main snapshot. The browser matrix covered login and 2FA, file list and folders, upload/chunk progress and failure, encryption controls, pending approval and approve/reject, preview/download, share creation and password flow, versions, rename/move, file and folder permissions, temporary expiry, trash/restore/permanent delete, admin/users/groups, quarantine, audit/export, backup creation/manifest/restore confirmation, and restore restart recovery. It also covered mobile navigation, permission-denied/error states, realtime refresh with dirty-form preservation, and responsive layout.

Viewports were desktop, 390px compact/mobile, and tablet-sized. Checks included keyboard navigation/focus, dialogs and labels, destructive-action clarity, loading/empty/error states, horizontal overflow, console output, mutation methods, and CSRF behavior. Restore and destructive actions used disposable fixtures only. The tested flows completed without a persistent UI defect; a one-time reconnect message after a test-server restart cleared on reload. Per-flow screenshots and a machine-readable browser trace were not retained, so this is operator-observed browser evidence, not a reusable automated acceptance suite. Browser session-expiry validation used a correctly signed test JWT expired by five minutes, set as an `HttpOnly` cookie in Playwright CLI against the same `62390` runtime. Navigating to `/index.html` caused `GET /auth/me` to return 401 and redirected to `/login.html?returnTo=%2Findex.html`; 401 resource errors appeared in the browser console. Logout invalidation was also confirmed. Automated auth tests cover session revocation; no separate browser flow waited for a live eight-hour token to expire.

The user authorized permanent cleanup of the exact fixture name `closure-ui-sample.txt` on test port 62376. A current read-only check found no share with that exact name; the only visible public share is named `closure-ui-renamed.txt` and is expired. It was left untouched because its identity as the authorized target could not be confirmed from the available unauthenticated session.

### Restore semantics and current residual

PR #123 corrected provider-inventory recovery: selected archive entries are validated, provider reconciliation intent is durably queued, lease/backoff and restart recovery are deterministic, and provider failures fail closed before the listener acknowledges readiness. Local restore uses verified preimages/compensation for quarantine, JSON, uploads, SQLite state/sidecars, and migration/restart recovery. Failure-injection tests cover local restore stages, migration rollback/retry, provider failure, pending reconciliation, and restart.

Restore is **not globally atomic** across local storage and external provider APIs. Provider operations cannot join a portable local filesystem/SQLite transaction; external writers are outside the restore gate; and Windows does not provide the same portable directory-entry flush guarantee as POSIX. The bounded semantics are local compensation/restart recovery plus durable, idempotent, resumable provider reconciliation. See [the restore transaction boundary](../backup-restore-transaction-boundary.md).

### Mission status at this snapshot

`PARTIAL`: the docs follow-up, final-SHA release gate, and fresh independent final review remained pending. No claim of production readiness or end-to-end Zero-Knowledge is made. Open issues and PRs remain open for their documented acceptance gaps.

## Historical status at the `fd995b2` snapshot

`PARTIAL` at the verification snapshot before this documentation-only follow-up. The latest queried `Root/main` SHA was `fd995b2ae587140db8ea1ba9de62cf7557ee0516`; exact-SHA push Security Regression, CodeQL, Dependency Review, and Pages checks passed. The prior execution record reports that the clean Windows local release gate passed on that SHA, but its exact output was not retained in the repository. The full browser matrix is incomplete, so complete UI acceptance is unproven. Whole restore remains locally rollback-recoverable with durable provider reconciliation, not globally atomic across storage providers.

This dated report is not production-readiness or release authorization.

## Historical execution record

- Mission baseline: `1df5e4640d4aea7dc700f2088059f489c2e51af0`.
- Live default branch after PR #117: `Root/main` at `14428690bef7c02648fd0be9570aabb17ae6de1a`.
- Latest queried default branch after PR #116: `Root/main` at `fd995b2ae587140db8ea1ba9de62cf7557ee0516`, the merge commit for PR #116.
- PR #116 head `73f3c67fde4817772544866aaa311141d137ebba` was merged on 2026-10-08. The prior candidate at `cdx/final-closure-evidence` is now published; this follow-up reconciles current-state documentation on a branch from the exact live main SHA.
- Unrelated worktrees and `.playwright-cli` artifacts were left untouched.
- Merged mission PRs: #101 at `5c86bd2a9844fdf21921f08cf2bf9d9a7253d652`; #103 at `f85cb389f3152191d612fb36b1ad97bde89ba99a`; #99 at `9e070823f2ee6372521a53d2fc130701ed074aab`; #114 at `566a3d24591423c624ef3bcb82290a77ff359210`; #115 at `b12d6286a867f1562ea6a9c557f8bd93fadfd5c1`; #117 at `14428690bef7c02648fd0be9570aabb17ae6de1a`; #118 at `1c2f7a8b276e63e53555f5de824afc9b7a9aa55e`; and #116 at `fd995b2ae587140db8ea1ba9de62cf7557ee0516`.

## Historical findings and corrections

| Severity / component | Evidence, fix, regression, status |
|---|---|
| High — bootstrap credentials | #114 removed implicit predictable production defaults and kept a test/development-only seed path. Clean-install, seed, test/development, and production-mode regressions are in the auth/bootstrap suite. Merged; exact-main suite passed. |
| High — CSRF / mutation methods | #114 moved approve/reject/trash mutations off GET, updated browser calls, and rejects legacy GET mutation. Route regressions cover no mutation on GET, CSRF enforcement, authorization, and audit behavior. Merged; exact-main suite passed. |
| High — proxy/client IP | #114 added explicit `TRUSTED_PROXIES` policy, ignores forwarding headers from untrusted peers, and documents proxy-hop/Cloudflare configuration. Tests cover direct origin, spoofed headers, trusted peers, and hop parsing. Deployment topology remains operator evidence. |
| Medium — default-branch CI | #114 added push validation for `Root/main` while keeping PR validation. Security Regression, CodeQL, dependency review, and Pages also passed on the later exact merge SHA `fd995b2…`. |
| High — restore recovery | #114 stages verified preimages, compensates local quarantine/JSON/upload/SQLite mutations, recovers before migrations after restart, and persists retryable provider reconciliation. Failure injection covers local stages, migration, provider failure, pending work, and restart. Local rollback is recoverable; whole restore is not globally atomic. |
| Medium — roadmap drift | #99 reconciled the roadmap. The ledger now records the live post-#116 merge snapshot at `fd995b2…`, with `1c2f7a8…` and earlier candidate snapshots labeled historical. The remaining open PR and issue acceptance boundaries are explicit. |
| Historical assessment, 2026-10-08 — `/auth/session.js` (superseded) | The source/spec review incorrectly assumed a bare classic script request omits credentials, and the sibling-origin browser probe was not completed at that snapshot. A disposable same-site sibling-port browser probe on 2026-10-09 later reproduced disclosure of username, role, and permission metadata. The route-scoped `Cross-Origin-Resource-Policy: same-origin` and foreign-Origin rejection, with current evidence, are recorded in `docs/security/browser-session-threat-model.md`. |

## Historical exact-SHA validation — `Root/main` `fd995b2ae587140db8ea1ba9de62cf7557ee0516`

Push Security Regression [#37731545082](https://github.com/bielxdh3/Root.ark/actions/runs/37731545082) passed on this exact SHA: Ubuntu Node 22 ran 938 tests (927 passed, 11 skipped, 0 failed) and Windows Node 22 ran 938 tests (934 passed, 4 skipped, 0 failed). CodeQL [#37731545119](https://github.com/bielxdh3/Root.ark/actions/runs/37731545119), default-branch Dependency Review [#37731544965](https://github.com/bielxdh3/Root.ark/actions/runs/37731544965), and Pages [#37731544171](https://github.com/bielxdh3/Root.ark/actions/runs/37731544171) passed.

The mission execution record reports that the validation checkout was clean and matched both `HEAD` and fetched `origin/Root/main` at `fd995b2…`, and that `node scripts/validate-release-gate.js` passed there with 21 passed, 0 blocked, and 0 failed. The exact command output was not retained in the repository. The available release-gate artifact, [`2026-10-08-rootark-final-release-gate-0085253.txt`](2026-10-08-rootark-final-release-gate-0085253.txt), is for a different SHA and records 254 files scanned, so it does not verify the `fd995b2…` result or the separately reported 255-file secret scan. Re-run and retain final-SHA evidence after the documentation-only merge.

## Historical exact-SHA validation — `Root/main` `14428690bef7c02648fd0be9570aabb17ae6de1a`

The remote checks in the historical table below ran on this exact SHA. The later post-#118 snapshot at `1c2f7a8…` is also preserved as historical evidence, not validation of the current or any subsequent default-branch SHA.

The post-#118 exact `Root/main` push validation at `1c2f7a8b276e63e53555f5de824afc9b7a9aa55e` passed: Security Regression [#37729789854](https://github.com/bielxdh3/Root.ark/actions/runs/37729789854), Ubuntu 938 total (927 passed, 11 skipped, 0 failed) and Windows 938 total (934 passed, 4 skipped, 0 failed); CodeQL [#37729789865](https://github.com/bielxdh3/Root.ark/actions/runs/37729789865), default-branch Dependency Review [#37729789780](https://github.com/bielxdh3/Root.ark/actions/runs/37729789780), and Pages [#37729789584](https://github.com/bielxdh3/Root.ark/actions/runs/37729789584) passed. This is not validation of any later default-branch SHA.

| Check | Result |
|---|---|
| Security Regression push [#37720151580](https://github.com/bielxdh3/Root.ark/actions/runs/37720151580) | Success. Ubuntu Node 22: 938 total, 927 passed, 11 skipped, 0 failed. Windows Node 22: 938 total, 934 passed, 4 skipped, 0 failed. Syntax, runtime-artifact, locked-dependency audit, and clean-checkout gates passed on both jobs. |
| CodeQL [#37720151634](https://github.com/bielxdh3/Root.ark/actions/runs/37720151634) | Success. |
| Dependency Review [#37720151454](https://github.com/bielxdh3/Root.ark/actions/runs/37720151454) | Success. |
| Pages [#37720150655](https://github.com/bielxdh3/Root.ark/actions/runs/37720150655) | Success. |

One moderate Dependabot alert remains open: `GHSA-hp3w-g68c-fv3c` for transitive `sprintf-js`; GitHub lists no first patched version. The earlier local gate on `0085253…` is historical. `node scripts/validate-release-gate.js` passed on clean Windows candidate SHA `df38a8a5e78ce3fa4154e6e55e63719a810a767b` with Node `v24.14.1`: 21 passed, 0 blocked, 0 failed. The same gate also passed on exact published PR head `a72d2f21db25363dc3f13d8816e3db3bd1ee2d93`: 21 passed, 0 blocked, 0 failed.

## Historical GitHub snapshot at query time before the PR #116 update

Open issues: #63 protected search; #64 native Android; #65 Zero-Knowledge runtime; #66 selective sync / Files On-Demand; #67 destructive-change protection; #68 capability sharing; #94 shared/topology-aware chunk-upload limits. None is closed by this mission.

| PR | State at query | Remaining boundary |
|---|---|---|
| #95 | Head `95d99e4a934384fcfa2101dfc210741cd791a3d1`; stale base `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1`; listed checks pass; 4 review threads resolved. | #94 still lacks proven deployment-wide rate limits/topology. |
| #97 | Head `a6a33a92cd6902f303254e60031da4bdc04cec04`; stale base `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1`; listed checks pass; 5 threads resolved. | Metadata-only listing/pagination, native Files On-Demand, and external-writer-safe eviction remain incomplete. |
| #102 | Head `e4dac5fb6527f36a3a8193f545d5c00753adafcd`; base `9de3c85ab59aa16fc46916abc0cf638c539086ef`; CodeQL fails, other listed checks pass; one unresolved thread at `services/internalFile.js:31`. | Keep open until the finding/thread is resolved and current-base checks pass. |
| #116 | At this historical query, remote head was `daa6025e0c08c29a4d4cc0b55ec9fbb31b7e4fca`, base `9e070823f2ee6372521a53d2fc130701ed074aab`, with no review threads. Its earlier Ubuntu run failed on an async cloud-restore test race. | #117 fixed the race on main. The candidate was subsequently updated and its later exact-head checks are recorded below. |

## Historical PR #116 candidate snapshot — head `a72d2f2…`

At exact PR head `a72d2f21db25363dc3f13d8816e3db3bd1ee2d93`, based on `Root/main` `14428690bef7c02648fd0be9570aabb17ae6de1a`, PR #116 was open and GitHub reported merge state `CLEAN`. Security Regression [run `37724164304`](https://github.com/bielxdh3/Root.ark/actions/runs/37724164304) passed: Ubuntu 938 total (927 passed, 11 skipped, 0 failed), Windows 938 total (934 passed, 4 skipped, 0 failed). CodeQL [run `37724164443`](https://github.com/bielxdh3/Root.ark/actions/runs/37724164443) and PR Dependency Review [run `37724164372`](https://github.com/bielxdh3/Root.ark/actions/runs/37724164372) passed; the default-branch dependency-review job was skipped as expected for a PR event. At query time there were no submitted GitHub reviews or review threads on #116. A fresh native review found the old-head wording identified above; this follow-up corrects it, so these checks apply to `a72d2f2…`, while the corrected head must be checked again.

## Historical PR #116 candidate snapshot before merge — 2026-10-08

At exact PR head `448d1c1ecd2cd3a1391dd741027dc146be3735b6`, based on `Root/main` `14428690bef7c02648fd0be9570aabb17ae6de1a`, PR #116 was open with GitHub merge state `CLEAN`. Security Regression [run `37725263473`](https://github.com/bielxdh3/Root.ark/actions/runs/37725263473) passed: Ubuntu Node 22 938 total (927 passed, 11 skipped, 0 failed); Windows Node 22 938 total (934 passed, 4 skipped, 0 failed). CodeQL [run `37725263468`](https://github.com/bielxdh3/Root.ark/actions/runs/37725263468) and PR Dependency Review [run `37725263466`](https://github.com/bielxdh3/Root.ark/actions/runs/37725263466) passed. The default-branch dependency-review job was skipped for the PR event. GitHub showed no submitted reviews or review threads on #116 at query time.

The local release gate passed on earlier code-equivalent candidate head `a72d2f2…` with 21 passed, 0 blocked, 0 failed. The `448d1c1…` follow-up changed documentation only; Security Regression's exact-head jobs also passed syntax, runtime-artifact, locked-dependency audit, and clean-checkout steps. That candidate later advanced to exact PR #116 head `73f3c67…`, passed Security Regression, CodeQL, and Dependency Review, and merged at `fd995b2…`; the run IDs are recorded above. A fresh independent review found stale `a72d2f2…` status wording in the earlier candidate; this update records the merged state.

## Historical restore semantics and residuals

PR #118 added a migration-stage failure injection to `test/backup-restore-transaction-boundary.test.js`. It verifies a failure inside migration SQL rolls back that migration's SQLite transaction, leaves the already-committed restored database authoritative, retains the fail-closed `restart_required` coordinator and preimage, and retries the migration on restart before the listener is acknowledged. The focused test passed 1/1 locally; exact-head PR and subsequent main-push checks passed. This confirms forward retry after the local restore commit, not whole-restore rollback at this stage.

Before local mutation, restore verifies preimages for quarantine, JSON data, uploads, SQLite files/sidecars, and restore policy. A pre-commit interruption is rolled back at startup before migrations or request handling. If recovery cannot safely complete, the service stays blocked for operator recovery. After local commit, cloud reconciliation is persisted, leased, idempotent, retryable, and resumed after restart. Provider APIs cannot join a portable local filesystem/SQLite transaction.

Residuals: external writers are outside the restore gate; persistent rollback failure may require operator help; Windows lacks the same portable directory-entry flush guarantee as POSIX; fake providers do not prove live interoperability. See [the restore transaction boundary](../backup-restore-transaction-boundary.md).

## Historical browser / UI validation

The fresh browser pass used the candidate code at `f2d171d…` in a disposable `NODE_ENV=test` runtime at `127.0.0.1:62379`. Its application code matched `Root/main` `1442869…`; intervening source changes were documentation-only. An earlier, separate disposable runtime at `127.0.0.1:62376` executed a backup restore and reached the expected restart-required barrier. In the fresh `62379` pass, the restore warning was opened and canceled. Neither session used user-instance data.

Operator-observed during browser interaction, without a retained per-flow trace or screenshot artifact: admin login/TOTP/logout; file list; folder create/navigation, one-hour expiry, Trash and restore; admin users/groups/quarantine; dirty group-form preservation during user refresh; non-admin denial on admin route; audit table and CSV download event; backup creation, manifest (`cloud_complete: false`), and restore warning/cancel. The earlier browser report recorded `closure-ui-sample.txt` as a disposable fixture on `127.0.0.1:62376`. In the latest bounded cleanup attempt, `/health` returned 200, but no authenticated session was available to confirm that exact item through the application UI; no deletion was performed, and the fixture's current presence is unverified. The cleanup authorization does not constitute full permanent-delete acceptance.

Desktop screenshot was approximately 1264×720. At 390×844 the document width was 375 px; at 820×1024 it was 805 px. No horizontal overflow was measured. Mobile navigation opened and closed with Escape; the skip link received keyboard focus and activated with Enter. The permission-denied mobile state was captured. Console warning/error count after these flows was zero.

A later fresh Playwright CLI session used the disposable runtime at `127.0.0.1:62376`. It authenticated as the sample non-admin user, selected tracked `README.md` through the CLI `upload` command, and submitted it: `POST /upload?folderId=root` returned 200 and the file appeared in pending approvals. Preview returned 200 from `/preview/text/pending/README.md?folderId=root`; Escape closed it. The encryption option exposed its labeled password field, then was reset without submitting. At 390×844, 820×1024, and 1264×720 the document/body width matched the viewport; mobile navigation opened and Escape closed it; keyboard Tab reached the profile summary with a visible focus outline. Logout returned `POST /auth/logout` 204 and subsequent `/auth/me` returned 401. The login inputs rendered `autocomplete=username` and `autocomplete=current-password`, so the tested login fields had the expected autofill tokens. During authenticated actions there were zero console errors/warnings; the expected unauthenticated `/auth/me` responses before login and after logout were 401. The runtime checkout was at `3c113718…`; comparison with `Root/main` `1442869…` showed differences only in documentation and tests, and its `server.js` hash matched the candidate.
A separate disposable `NODE_ENV=test`, `DB_ENABLED=false` runtime used generated fixture accounts, a local provider, role-required TOTP, and generated test keys. Through Playwright UI, admin login first returned the enrollment-required 403 state; the enrollment and confirmation forms returned 200, then login, TOTP challenge, and `/auth/me` returned 200. The fixture TOTP was generated locally and entered in the UI; no code or secret was retained. The admin created a folder through the `Nova pasta` dialog (201), opened the access view (GET 200; canceled without saving), and renamed the folder through the `Renomear` dialog (PUT 200). The test-owned server process was stopped; its fixture runtime was preserved. No file was approved, rejected, or deleted.

Still unproven in the available browser sessions: chunk progress/failure, approve/reject, download, share creation/password flow, versions, move, permission mutations, nonempty quarantine, permanent-delete flow, session expiry/revocation independent of logout, and cross-tab realtime refresh. The earlier browser session left its test-owned README upload pending; it was not approved, rejected, or permanently deleted in that session. The existing account reached the TOTP challenge but no account code was used; the isolated fixture runtime above covered a limited admin 2FA/folder subset. The later authorized cleanup attempt could not confirm or delete `closure-ui-sample.txt` because no authenticated session to the `62376` service was available. Earlier operator-observed checks at `62379` and `9e070…` remain supplemental and have no retained per-flow trace. Full browser acceptance remains incomplete.

The final isolated browser attempt reached required TOTP enrollment but stopped before confirmation because the browser helper no longer had the enrollment key when it tried to produce a code. The test server was stopped and the browser session closed; no additional runtime/browser retry was made. The sibling-origin script probe, full admin mutation matrix, and authorized test-share creation therefore remain unverified. This does not affect the successful narrow login/session, upload, pending-preview, responsive-width, and keyboard observations above; it keeps browser acceptance `PARTIAL`.

## Historical security and remaining work

The merged fixes pass exact-main checks through `fd995b2…`. Restore recovery is bounded to local rollback plus durable provider reconciliation. The project is not production-ready on repository evidence alone: proxy ingress/topology, provider credentials/interoperability, native binding/deployment behavior, and operational recovery remain deployment gates. Root.ark is not an end-to-end Zero-Knowledge runtime; legacy server-readable paths remain. Existing bearer links are not operation-scoped capabilities.

PR #116 is merged. At this snapshot, issues #63–68 and #94 and incomplete PRs #95/#97/#102 remain open. The full browser matrix is incomplete. This report predates the documentation-only reconciliation based on `fd995b2…`; that change requires its own exact-head review and exact post-merge `Root/main` validation, recorded in the final mission report.
