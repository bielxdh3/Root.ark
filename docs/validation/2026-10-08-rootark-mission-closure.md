# Root.ark correction and closure validation — 2026-10-08

This report records the mission's final code validation and the live GitHub state queried on 2026-10-08 UTC. The validated source tree was `Root/main` at `9e070823f2ee6372521a53d2fc130701ed074aab`. This report is a documentation-only follow-up; its own merge SHA must be validated by the push-triggered default-branch workflows and is not represented by the source SHA below.

## Mission result

The security and release-correction candidate is merged. A fresh independent review of the baseline-to-`9e070823f2ee6372521a53d2fc130701ed074aab` changes found no actionable security or correctness issue. The release evidence below applies to the exact source SHA stated above.

## Merged correction work

| PR | Result | Evidence |
|---|---|---|
| #114 | Merged at `566a3d24591423c624ef3bcb82290a77ff359210` | Bootstrap fail-closed behavior, mutation-method/CSRF boundary, proxy/client-IP trust, default-branch validation trigger, restore rollback/recovery, and focused regressions. PR-head validation passed on Linux and Windows. |
| #115 | Merged at `b12d6286a867f1562ea6a9c557f8bd93fadfd5c1` | Increased only the dead-owner recovery test timeout from 40 ms to 5 seconds; production lock behavior and fail-closed assertions are unchanged. Exact-head validation passed on Linux and Windows. |
| #99 | Merged at `9e070823f2ee6372521a53d2fc130701ed074aab` | Reconciled the issue ledger, plan tree, README and restore-boundary documentation against the live snapshot. |

## Exact-SHA validation

The final validation worktree was clean and matched `Root/main` at `9e070823f2ee6372521a53d2fc130701ed074aab` after `git fetch origin Root/main`.

| Validation | Result |
|---|---|
| Push-triggered Security Regression, run `37716182470` | Success on this exact SHA. Ubuntu Node 22: 938 tests, 927 passed, 11 skipped, 0 failed. Windows Node 22: 938 tests, 934 passed, 4 skipped, 0 failed. Syntax, runtime-artifact guard, locked-dependency audit, and clean-checkout checks passed on both jobs. |
| CodeQL, run `37716182350` | Success on this exact SHA. |
| Dependency Review, run `37716182451` | Success on this exact SHA. |
| Pages build/deployment, run `37716181679` | Success on this exact SHA. |
| `node scripts/validate-release-gate.js` on the documentation PR head `00852536538eb8ac9261b1091d965f74bd9a6c22`, Windows, Node `v24.14.1` | 21 passed, 0 blocked, 0 failed. Captured output: [release-gate record](2026-10-08-rootark-final-release-gate-0085253.txt). It includes canonical `npm test`, syntax, runtime artifacts, dependency lock/provenance, high-severity npm audit, focused security/restore suites, 254-file secret-pattern scan, and clean-worktree checks. |
| `git diff --check` | Passed. |

The lockfile audit passed the repository's high-severity gate. GitHub still reports one open moderate Dependabot alert, `GHSA-hp3w-g68c-fv3c` (`sprintf-js` via `package-lock.json`), with no first patched version currently listed.

## Live GitHub state at the source-SHA query

The seven open issues are #63 protected search, #64 native Android, #65 Zero-Knowledge runtime, #66 selective sync/Files On-Demand, #67 destructive-change protection, #68 capability sharing, and #94 shared/topology-aware chunk-upload rate limiting. Their acceptance criteria remain incomplete; none is closed by this mission.

| Open PR | Exact head | Live checks and remaining state |
|---|---|---|
| #95 | `95d99e4a934384fcfa2101dfc210741cd791a3d1` | CodeQL, Analyze, dependency review, Ubuntu and Windows pass on this head; base is stale, merge state is dirty, and #94 still needs shared/edge enforcement or verified deployment topology. |
| #97 | `a6a33a92cd6902f303254e60031da4bdc04cec04` | CodeQL, Analyze, dependency review, Ubuntu and Windows pass on this head; base is stale and selective-sync acceptance remains partial. |
| #102 | `e4dac5fb6527f36a3a8193f545d5c00753adafcd` | CodeQL fails (74 high and 5 medium findings); one unresolved review thread remains at `services/internalFile.js:31`. Do not merge until corrected and revalidated. |

There are no unresolved review threads on the merged mission PRs #99 or #115. Existing partial-feature PRs remain open for their documented acceptance gaps.

## Restore semantics and residual boundary

Restore stages and verifies local preimages before mutation, applies compensating rollback for locally controlled JSON, quarantine, upload-tree and SQLite state, and uses a durable restart-required barrier when recovery cannot safely finish. Provider reconciliation is persisted and retryable after the local authoritative commit. Failure-injection tests cover pre-commit, quarantine/filesystem, SQLite/migration, provider failure, pending reconciliation and restart recovery.

Restore is **not globally atomic** across those local storage domains and external providers. Provider APIs cannot join a portable filesystem/SQLite transaction. On Windows, directory-entry fsync is unavailable through the current Node implementation, so the same power-loss durability guarantee is not claimed as on POSIX. Failed preimage recovery may require operator assistance. These limits are described in [the restore transaction boundary](../backup-restore-transaction-boundary.md).

## Browser acceptance

The manual real-browser matrix was performed against the disposable local application on desktop, 390 px compact/mobile and 820 px tablet widths. The run reported coverage of login/2FA, file and folder navigation, upload/chunk progress and encryption controls, approval/rejection, preview/download, share creation/password unlock, versions, rename/move, file and folder permissions, expiration, trash/restore, admin/users/groups, quarantine, audit/export, backup/manifest/restore confirmation, denied/error states, responsive layout, keyboard/focus, session expiry, realtime refresh and dirty-form preservation. The full sanitized per-flow trace was not retained, so this coverage is an operator-reported manual result rather than a replayable browser artifact; it does not establish complete browser acceptance by itself.

Available console logs include a 401 on `/auth/me` during unauthenticated page initialization, plus 401/403/415 responses in the share/access flow and a 503 on `/auth/2fa/enroll`; the retained snapshots do not fully attribute those responses to a specific expected negative test. After restore, the server correctly required restart and returned 503 for page assets while the recovery barrier was active. Accordingly this report does not claim a clean console; the 2FA endpoint response remains an unclassified browser evidence limitation. Mutation requests were observed using non-safe methods. The test fixture remains in the disposable trash; permanent deletion is pending explicit action-time confirmation.

A backup restore was then executed only against the disposable server and showed the expected restart-required barrier; the backup controls were disabled afterward. The `closure-ui-sample.txt` fixture remains in the disposable trash. Permanent deletion was not executed pending explicit action-time confirmation; no user-instance data was touched.

