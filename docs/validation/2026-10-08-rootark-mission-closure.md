# Root.ark closure validation — 2026-10-08

## Status

`PARTIAL`. The security corrections are merged and exact `Root/main` CI passed at `14428690bef7c02648fd0be9570aabb17ae6de1a`. PR #116 is already open, but its remote branch still has an older head and base; update it with this candidate and the merged current base, then obtain review, validation, and merge. The full browser acceptance matrix is incomplete because file selection did not attach a test fixture through the in-app browser adapter. Whole restore remains rollback-recoverable locally, not globally atomic across storage providers.

This dated report is not production-readiness or release authorization.

## Execution record

- Mission baseline: `1df5e4640d4aea7dc700f2088059f489c2e51af0`.
- Live default branch after PR #117: `Root/main` at `14428690bef7c02648fd0be9570aabb17ae6de1a`.
- Candidate: `cdx/final-closure-evidence`. Local HEAD before this documentation update: `f2d171d5338e543a9c752dff1e77bd56f0f994a6`. Remote PR #116 still pointed to `daa6025e0c08c29a4d4cc0b55ec9fbb31b7e4fca` at query time.
- This candidate is documentation-only. Unrelated workspace files and the cloud-access worktree were left untouched.
- Merged PRs: #114 at `566a3d24591423c624ef3bcb82290a77ff359210`; #115 at `b12d6286a867f1562ea6a9c557f8bd93fadfd5c1`; #99 at `9e070823f2ee6372521a53d2fc130701ed074aab`; #117 at `14428690bef7c02648fd0be9570aabb17ae6de1a`.

## Findings and corrections

| Severity / component | Evidence, fix, regression, status |
|---|---|
| High — bootstrap credentials | #114 removed implicit predictable production defaults and kept a test/development-only seed path. Clean-install, seed, test/development, and production-mode regressions are in the auth/bootstrap suite. Merged; exact-main suite passed. |
| High — CSRF / mutation methods | #114 moved approve/reject/trash mutations off GET, updated browser calls, and rejects legacy GET mutation. Route regressions cover no mutation on GET, CSRF enforcement, authorization, and audit behavior. Merged; exact-main suite passed. |
| High — proxy/client IP | #114 added explicit `TRUSTED_PROXIES` policy, ignores forwarding headers from untrusted peers, and documents proxy-hop/Cloudflare configuration. Tests cover direct origin, spoofed headers, trusted peers, and hop parsing. Deployment topology remains operator evidence. |
| Medium — default-branch CI | #114 added push validation for `Root/main` while keeping PR validation. Security Regression ran on exact SHA `1442869…`; CodeQL and dependency review also passed there. |
| High — restore recovery | #114 stages verified preimages, compensates local quarantine/JSON/upload/SQLite mutations, recovers before migrations after restart, and persists retryable provider reconciliation. Failure injection covers local stages, migration, provider failure, pending work, and restart. Local rollback is recoverable; whole restore is not globally atomic. |
| Medium — roadmap drift | #99 reconciled the roadmap; this update records the post-#117 source SHA and live issue/PR snapshot. PR #116 still requires publication and review. |

## Exact-SHA validation

All remote checks below ran on exact `Root/main` SHA `14428690bef7c02648fd0be9570aabb17ae6de1a`.

| Check | Result |
|---|---|
| Security Regression push [#37720151580](https://github.com/bielxdh3/Root.ark/actions/runs/37720151580) | Success. Ubuntu Node 22: 938 total, 927 passed, 11 skipped, 0 failed. Windows Node 22: 938 total, 934 passed, 4 skipped, 0 failed. Syntax, runtime-artifact, locked-dependency audit, and clean-checkout gates passed on both jobs. |
| CodeQL [#37720151634](https://github.com/bielxdh3/Root.ark/actions/runs/37720151634) | Success. |
| Dependency Review [#37720151454](https://github.com/bielxdh3/Root.ark/actions/runs/37720151454) | Success. |
| Pages [#37720150655](https://github.com/bielxdh3/Root.ark/actions/runs/37720150655) | Success. |

One moderate Dependabot alert remains open: `GHSA-hp3w-g68c-fv3c` for transitive `sprintf-js`; GitHub lists no first patched version. The older local release-gate run on `0085253…` is historical, not evidence for this SHA. A fresh release-gate run on the published documentation candidate remains pending.

## Live GitHub snapshot at query time

Open issues: #63 protected search; #64 native Android; #65 Zero-Knowledge runtime; #66 selective sync / Files On-Demand; #67 destructive-change protection; #68 capability sharing; #94 shared/topology-aware chunk-upload limits. None is closed by this mission.

| PR | State at query | Remaining boundary |
|---|---|---|
| #95 | Head `95d99e4a934384fcfa2101dfc210741cd791a3d1`; stale base `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1`; listed checks pass; 4 review threads resolved. | #94 still lacks proven deployment-wide rate limits/topology. |
| #97 | Head `a6a33a92cd6902f303254e60031da4bdc04cec04`; stale base `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1`; listed checks pass; 5 threads resolved. | Metadata-only listing/pagination, native Files On-Demand, and external-writer-safe eviction remain incomplete. |
| #102 | Head `e4dac5fb6527f36a3a8193f545d5c00753adafcd`; base `9de3c85ab59aa16fc46916abc0cf638c539086ef`; CodeQL fails, other listed checks pass; one unresolved thread at `services/internalFile.js:31`. | Keep open until the finding/thread is resolved and current-base checks pass. |
| #116 | Remote head `daa6025e0c08c29a4d4cc0b55ec9fbb31b7e4fca`, base `9e070823f2ee6372521a53d2fc130701ed074aab`, no review threads. Its earlier Ubuntu run failed on an async cloud-restore test race. | #117 fixed the race on main; publish the candidate merge and get new exact-head checks/review. |

## Restore semantics and residuals

Before local mutation, restore verifies preimages for quarantine, JSON data, uploads, SQLite files/sidecars, and restore policy. A pre-commit interruption is rolled back at startup before migrations or request handling. If recovery cannot safely complete, the service stays blocked for operator recovery. After local commit, cloud reconciliation is persisted, leased, idempotent, retryable, and resumed after restart. Provider APIs cannot join a portable local filesystem/SQLite transaction.

Residuals: external writers are outside the restore gate; persistent rollback failure may require operator help; Windows lacks the same portable directory-entry flush guarantee as POSIX; fake providers do not prove live interoperability. See [the restore transaction boundary](../backup-restore-transaction-boundary.md).

## Browser / UI validation

The fresh browser pass used the candidate code at `f2d171d…` in a disposable `NODE_ENV=test` runtime at `127.0.0.1:62379`. Its application code matched `Root/main` `1442869…`; intervening source changes were documentation-only. An earlier, separate disposable runtime at `127.0.0.1:62376` executed a backup restore and reached the expected restart-required barrier. In the fresh `62379` pass, the restore warning was opened and canceled. Neither session used user-instance data.

Operator-observed during browser interaction, without a retained per-flow trace or screenshot artifact: admin login/TOTP/logout; file list; folder create/navigation, one-hour expiry, Trash and restore; admin users/groups/quarantine; dirty group-form preservation during user refresh; non-admin denial on admin route; audit table and CSV download event; backup creation, manifest (`cloud_complete: false`), and restore warning/cancel. The disposable `closure-ui-sample.txt` fixture was permanently deleted only after the user authorized that exact action on `127.0.0.1:62376`; Trash was then confirmed empty. That single cleanup does not constitute full permanent-delete acceptance.

Desktop screenshot was approximately 1264×720. At 390×844 the document width was 375 px; at 820×1024 it was 805 px. No horizontal overflow was measured. Mobile navigation opened and closed with Escape; the skip link received keyboard focus and activated with Enter. The permission-denied mobile state was captured. Console warning/error count after these flows was zero.

Not proven in this run: successful file selection/upload, chunk progress/failure, pending approve/reject, preview/download, share password flow, versions, rename/move, permission mutation, nonempty quarantine, session expiry, and cross-tab realtime refresh. The documented chooser flow returned without populating the input for either a temporary fixture path or a workspace-accessible fixture path, so no upload request was submitted. The one authorized fixture deletion above is narrow cleanup evidence, not a complete delete-flow matrix. Older local browser observations at `9e070…` are supplemental, not replayable final-candidate evidence. Full browser acceptance remains incomplete.

## Security and remaining work

The merged fixes pass exact-main checks. Restore recovery is bounded to local rollback plus durable provider reconciliation. The project is not production-ready on repository evidence alone: proxy ingress/topology, provider credentials/interoperability, native binding/deployment behavior, and operational recovery remain deployment gates. Root.ark is not an end-to-end Zero-Knowledge runtime; legacy server-readable paths remain. Existing bearer links are not operation-scoped capabilities.

Pending: update the existing PR #116 with this candidate and the current base; run exact-head Linux/Windows, CodeQL, dependency review and release gate; obtain fresh independent review; merge only after gates pass; then fetch and validate the new exact `Root/main` SHA and conduct a fresh final review. Keep #63–68 and #94, and incomplete PRs #95/#97/#102, open.
