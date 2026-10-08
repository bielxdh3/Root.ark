# Root.ark closure validation — 2026-10-08

## Status

`PARTIAL` at the latest recorded GitHub query after PR #118: `Root/main` was `1c2f7a8b276e63e53555f5de824afc9b7a9aa55e`; its exact-SHA Security Regression, CodeQL, Dependency Review, and Pages checks passed. At that query, remote PR #116 was still at head `75efa003136c0799cf678fa8ad264076893882d3` on the earlier base `14428690bef7c02648fd0be9570aabb17ae6de1a`. The candidate branch has since been refreshed locally with PR #118's merge. The full browser matrix is incomplete, so no complete closure verdict is justified. Whole restore remains rollback-recoverable locally, not globally atomic across storage providers.

This dated report is not production-readiness or release authorization.

## Execution record

- Mission baseline: `1df5e4640d4aea7dc700f2088059f489c2e51af0`.
- Live default branch after PR #117: `Root/main` at `14428690bef7c02648fd0be9570aabb17ae6de1a`.
- Latest queried default branch after PR #118: `Root/main` at `1c2f7a8b276e63e53555f5de824afc9b7a9aa55e`.
- Candidate: `cdx/final-closure-evidence`. The refreshed local branch merged `origin/Root/main` at `1c2f7a8…` before these changes. Its remote PR #116 head at the re-query was `75efa003136c0799cf678fa8ad264076893882d3`; the candidate changes the README, issue ledger, plan tree, browser-session threat model, closure report, and test-only failure diagnostics.
- Unrelated worktrees and `.playwright-cli` artifacts were left untouched.
- Merged mission PRs: #101 at `5c86bd2a9844fdf21921f08cf2bf9d9a7253d652`; #103 at `f85cb389f3152191d612fb36b1ad97bde89ba99a`; #99 at `9e070823f2ee6372521a53d2fc130701ed074aab`; #114 at `566a3d24591423c624ef3bcb82290a77ff359210`; #115 at `b12d6286a867f1562ea6a9c557f8bd93fadfd5c1`; #117 at `14428690bef7c02648fd0be9570aabb17ae6de1a`; and #118 at `1c2f7a8b276e63e53555f5de824afc9b7a9aa55e`.

## Findings and corrections

| Severity / component | Evidence, fix, regression, status |
|---|---|
| High — bootstrap credentials | #114 removed implicit predictable production defaults and kept a test/development-only seed path. Clean-install, seed, test/development, and production-mode regressions are in the auth/bootstrap suite. Merged; exact-main suite passed. |
| High — CSRF / mutation methods | #114 moved approve/reject/trash mutations off GET, updated browser calls, and rejects legacy GET mutation. Route regressions cover no mutation on GET, CSRF enforcement, authorization, and audit behavior. Merged; exact-main suite passed. |
| High — proxy/client IP | #114 added explicit `TRUSTED_PROXIES` policy, ignores forwarding headers from untrusted peers, and documents proxy-hop/Cloudflare configuration. Tests cover direct origin, spoofed headers, trusted peers, and hop parsing. Deployment topology remains operator evidence. |
| Medium — default-branch CI | #114 added push validation for `Root/main` while keeping PR validation. Security Regression ran on exact SHA `1442869…`; CodeQL and dependency review also passed there. |
| High — restore recovery | #114 stages verified preimages, compensates local quarantine/JSON/upload/SQLite mutations, recovers before migrations after restart, and persists retryable provider reconciliation. Failure injection covers local stages, migration, provider failure, pending work, and restart. Local rollback is recoverable; whole restore is not globally atomic. |
| Medium — roadmap drift | #99 reconciled the roadmap. Older post-#117 and PR #116 candidate snapshots remain explicitly historical; the refreshed ledger records the post-#118 `Root/main` SHA `1c2f7a8…` and the PR/issue state at the latest query. The current PR #116 head must pass its own exact-head checks after this candidate is published. |
| No confirmed cross-origin identity leak — `/auth/session.js` | The endpoint is authenticated and no-store, but no tracked page loads it, default cross-origin classic-script requests omit same-origin credentials, and the application emits no credentialed CORS headers. An independent source/standards review did not confirm a reachable leak. The threat model was corrected; the sibling-origin browser probe was not completed, so reassess if credentialed CORS is enabled at the app or proxy. |

## Exact-SHA validation

All remote checks below ran on exact `Root/main` SHA `14428690bef7c02648fd0be9570aabb17ae6de1a`.

The later exact `Root/main` push validation for PR #118's merge at `1c2f7a8b276e63e53555f5de824afc9b7a9aa55e` also passed: Security Regression [#37729789854](https://github.com/bielxdh3/Root.ark/actions/runs/37729789854), Ubuntu 938 total (927 passed, 11 skipped, 0 failed) and Windows 938 total (934 passed, 4 skipped, 0 failed); CodeQL [#37729789865](https://github.com/bielxdh3/Root.ark/actions/runs/37729789865), default-branch Dependency Review [#37729789780](https://github.com/bielxdh3/Root.ark/actions/runs/37729789780), and Pages [#37729789584](https://github.com/bielxdh3/Root.ark/actions/runs/37729789584) passed. This is not validation of any later default-branch SHA.

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

## Latest PR #116 candidate snapshot — 2026-10-08

At exact PR head `448d1c1ecd2cd3a1391dd741027dc146be3735b6`, based on `Root/main` `14428690bef7c02648fd0be9570aabb17ae6de1a`, PR #116 was open with GitHub merge state `CLEAN`. Security Regression [run `37725263473`](https://github.com/bielxdh3/Root.ark/actions/runs/37725263473) passed: Ubuntu Node 22 938 total (927 passed, 11 skipped, 0 failed); Windows Node 22 938 total (934 passed, 4 skipped, 0 failed). CodeQL [run `37725263468`](https://github.com/bielxdh3/Root.ark/actions/runs/37725263468) and PR Dependency Review [run `37725263466`](https://github.com/bielxdh3/Root.ark/actions/runs/37725263466) passed. The default-branch dependency-review job was skipped for the PR event. GitHub showed no submitted reviews or review threads on #116 at query time.

The local release gate passed on earlier code-equivalent candidate head `a72d2f2…` with 21 passed, 0 blocked, 0 failed. The 448d1c1 follow-up changed documentation only; Security Regression's exact-head jobs additionally passed syntax, runtime-artifact, locked-dependency audit, and clean-checkout steps. A fresh independent candidate review found stale `a72d2f2…` status wording in this documentation set; this follow-up records the 448d1c1 state. The corrected documentation head must receive its own checks and review before merge.

## Restore semantics and residuals

PR #118 added a migration-stage failure injection to `test/backup-restore-transaction-boundary.test.js`. It verifies a failure inside migration SQL rolls back that migration's SQLite transaction, leaves the already-committed restored database authoritative, retains the fail-closed `restart_required` coordinator and preimage, and retries the migration on restart before the listener is acknowledged. The focused test passed 1/1 locally; exact-head PR and subsequent main-push checks passed. This confirms forward retry after the local restore commit, not whole-restore rollback at this stage.

Before local mutation, restore verifies preimages for quarantine, JSON data, uploads, SQLite files/sidecars, and restore policy. A pre-commit interruption is rolled back at startup before migrations or request handling. If recovery cannot safely complete, the service stays blocked for operator recovery. After local commit, cloud reconciliation is persisted, leased, idempotent, retryable, and resumed after restart. Provider APIs cannot join a portable local filesystem/SQLite transaction.

Residuals: external writers are outside the restore gate; persistent rollback failure may require operator help; Windows lacks the same portable directory-entry flush guarantee as POSIX; fake providers do not prove live interoperability. See [the restore transaction boundary](../backup-restore-transaction-boundary.md).

## Browser / UI validation

The fresh browser pass used the candidate code at `f2d171d…` in a disposable `NODE_ENV=test` runtime at `127.0.0.1:62379`. Its application code matched `Root/main` `1442869…`; intervening source changes were documentation-only. An earlier, separate disposable runtime at `127.0.0.1:62376` executed a backup restore and reached the expected restart-required barrier. In the fresh `62379` pass, the restore warning was opened and canceled. Neither session used user-instance data.

Operator-observed during browser interaction, without a retained per-flow trace or screenshot artifact: admin login/TOTP/logout; file list; folder create/navigation, one-hour expiry, Trash and restore; admin users/groups/quarantine; dirty group-form preservation during user refresh; non-admin denial on admin route; audit table and CSV download event; backup creation, manifest (`cloud_complete: false`), and restore warning/cancel. The disposable `closure-ui-sample.txt` fixture was permanently deleted only after the user authorized that exact action on `127.0.0.1:62376`; Trash was then confirmed empty. That single cleanup does not constitute full permanent-delete acceptance.

Desktop screenshot was approximately 1264×720. At 390×844 the document width was 375 px; at 820×1024 it was 805 px. No horizontal overflow was measured. Mobile navigation opened and closed with Escape; the skip link received keyboard focus and activated with Enter. The permission-denied mobile state was captured. Console warning/error count after these flows was zero.

A later fresh Playwright CLI session used the disposable runtime at `127.0.0.1:62376`. It authenticated as the sample non-admin user, selected tracked `README.md` through the CLI `upload` command, and submitted it: `POST /upload?folderId=root` returned 200 and the file appeared in pending approvals. Preview returned 200 from `/preview/text/pending/README.md?folderId=root`; Escape closed it. The encryption option exposed its labeled password field, then was reset without submitting. At 390×844, 820×1024, and 1264×720 the document/body width matched the viewport; mobile navigation opened and Escape closed it; keyboard Tab reached the profile summary with a visible focus outline. Logout returned `POST /auth/logout` 204 and subsequent `/auth/me` returned 401. The login inputs rendered `autocomplete=username` and `autocomplete=current-password`, so the tested login fields had the expected autofill tokens. During authenticated actions there were zero console errors/warnings; the expected unauthenticated `/auth/me` responses before login and after logout were 401. The runtime checkout was at `3c113718…`; comparison with `Root/main` `1442869…` showed differences only in documentation and tests, and its `server.js` hash matched the candidate.
A separate disposable `NODE_ENV=test`, `DB_ENABLED=false` runtime used generated fixture accounts, a local provider, role-required TOTP, and generated test keys. Through Playwright UI, admin login first returned the enrollment-required 403 state; the enrollment and confirmation forms returned 200, then login, TOTP challenge, and `/auth/me` returned 200. The fixture TOTP was generated locally and entered in the UI; no code or secret was retained. The admin created a folder through the `Nova pasta` dialog (201), opened the access view (GET 200; canceled without saving), and renamed the folder through the `Renomear` dialog (PUT 200). The test-owned server process was stopped; its fixture runtime was preserved. No file was approved, rejected, or deleted.

Still unproven in the available browser sessions: chunk progress/failure, approve/reject, download, share creation/password flow, versions, move, permission mutations, nonempty quarantine, permanent-delete flow, session expiry/revocation independent of logout, and cross-tab realtime refresh. The new README upload remains pending in the separate 62376 disposable runtime; it was not approved, rejected, or permanently deleted. In that session, the existing account reached the TOTP challenge but no account code was used; the isolated fixture runtime above covered a limited admin 2FA/folder subset. The earlier authorized deletion of `closure-ui-sample.txt` was narrow cleanup evidence only; it does not prove the full permanent-delete flow. Earlier operator-observed checks at `62379` and `9e070…` remain supplemental and have no retained per-flow trace. Full browser acceptance remains incomplete.

The final isolated browser attempt reached required TOTP enrollment but stopped before confirmation because the browser helper no longer had the enrollment key when it tried to produce a code. The test server was stopped and the browser session closed; no additional runtime/browser retry was made. The sibling-origin script probe, full admin mutation matrix, and authorized test-share creation therefore remain unverified. This does not affect the successful narrow login/session, upload, pending-preview, responsive-width, and keyboard observations above; it keeps browser acceptance `PARTIAL`.

## Security and remaining work

The merged fixes pass exact-main checks through `1c2f7a8…`. Restore recovery is bounded to local rollback plus durable provider reconciliation. The project is not production-ready on repository evidence alone: proxy ingress/topology, provider credentials/interoperability, native binding/deployment behavior, and operational recovery remain deployment gates. Root.ark is not an end-to-end Zero-Knowledge runtime; legacy server-readable paths remain. Existing bearer links are not operation-scoped capabilities.

At the latest query, PR #116 still needed publication of the refreshed snapshot, exact-head checks, independent review, and merge. Afterward, validate the resulting exact `Root/main` SHA and conduct a fresh independent final review. The complete browser matrix remains incomplete. Keep #63–68 and #94, and incomplete PRs #95/#97/#102, open.
