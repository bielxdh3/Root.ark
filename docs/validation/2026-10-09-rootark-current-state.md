# Root.ark current validation and GitHub snapshot — 2026-10-09

## Verdict and scope

**Status: PARTIAL.** This is a point-in-time snapshot of application code at exact `Root/main` SHA `8771d87084e458202d77ab956e3d341c0fe4868f`, after PRs #141 and #142 and before the documentation-only follow-up prepared with this report. The mission baseline is `1df5e4640d4aea7dc700f2088059f489c2e51af0`, which is an ancestor of this source SHA. A later documentation merge changes the default-branch SHA and must receive its own exact-SHA validation; this snapshot does not substitute for that work.

The two mission PRs merged so far were:

| PR | Change | Head SHA | Merge SHA |
|---|---|---|---|
| [#141](https://github.com/bielxdh3/Root.ark/pull/141) | Revoke active sessions on logout | `f1a4fbaa22e2cfc78b53703b28639d935bfdd009` | `6005b5ea0fd69653066ae5283c101f43510d73aa` |
| [#142](https://github.com/bielxdh3/Root.ark/pull/142) | Keep keyboard focus inside shared dialogs | `e511134f56f5eae44569e3c1614295022fccb328` | `8771d87084e458202d77ab956e3d341c0fe4868f` |

## Exact-SHA validation

The following GitHub workflows ran on exact `Root/main` SHA `8771d87084e458202d77ab956e3d341c0fe4868f`:

| Check | Run | Platform/result |
|---|---|---|
| Security Regression | [#37931149881](https://github.com/bielxdh3/Root.ark/actions/runs/37931149881) | Ubuntu Node 22: 1,028 passed, 11 skipped, 0 failed; Windows Node 22: 1,032 passed, 7 skipped, 0 failed. Syntax and runtime-artifact checks passed on both; configured high-severity dependency audit passed on Ubuntu. |
| CodeQL | [#37931149727](https://github.com/bielxdh3/Root.ark/actions/runs/37931149727) | Passed. |
| Dependency Review | [#37931149738](https://github.com/bielxdh3/Root.ark/actions/runs/37931149738) | Passed on the default-branch push. |
| Pages | [#37931148943](https://github.com/bielxdh3/Root.ark/actions/runs/37931148943) | Passed. |

PR #142 also passed its exact-head Security Regression (#37927602855), CodeQL (#37927602875), and dependency-review checks (#37927602872); the push-triggered `Root/main` runs above validate the merge SHA separately.

### Local release-gate evidence and limitation

The immutable local validation checkout was exact PR #142 head `e511134f56f5eae44569e3c1614295022fccb328`, with Node 24.14.1/npm 11.11.0. The official `npm run validate:release-gate` did not produce a passing result: one attempt stopped in an upload-boundary stage and later hung in `test/backup-takeover-race.test.js`; a second completed as 20 passed, 0 blocked, 1 failed, with the final-head canonical `npm test` subgate returning exit 1. A direct `npm test` on that same immutable candidate completed with 1,026 passed, 13 skipped, and 0 failed; focused upload-security (31/31) and backup-takeover-race (1/1) tests also passed. An instrumented diagnostic mirror of the release-gate runner reported 21/21, but it is not the official command and is not counted as a passing release gate. Therefore the release gate remains unresolved, and must be run on the final exact `Root/main` SHA before closure.

## Browser and UI acceptance

Real-browser acceptance of the application flows was run on PR #141's exact source head `f1a4fbaa22e2cfc78b53703b28639d935bfdd009` in Chromium at 390×844, 768px, and 1440px viewports. It covered login, 2FA, logout/session behavior, file list and folders, ordinary and chunk uploads, encryption and expiration controls, pending approval/approve/reject, preview/download, share creation and password flow, versions, rename/move, file and folder permissions, trash/restore/permanent delete, admin/users/groups, audit/export, backup creation/manifest/restore confirmation and cancel, plus dirty-form preservation under realtime refresh. Network checks verified mutation methods and CSRF behavior; no browser console errors or warnings were observed. A fresh independent browser review of PR #142's dialog change reproduced the focus escape on the base and verified Tab/Shift+Tab remained inside the dialog on the candidate, including compact viewport behavior.

The quarantine empty state was exercised, but quarantine ingestion itself was not proven in a real browser. A disposable test-server launch for that path was rejected by the environment safety layer; the path remains unverified, not passed. Keyboard focus, dialogs, responsive layout, and destructive confirmation were reviewed for the affected flows. This does not constitute production browser testing or prove every deployment-specific provider flow.

## Restore semantics

Restore stages verified local pre-images and a durable coordinator before local mutation. It applies quarantine, restorable filesystem data, uploads, SQLite files/sidecars, and restore-derived provider suppression in sequence. If interrupted after the prepared boundary, startup verifies and restores local pre-images in reverse order; missing/corrupt recovery state fails closed for operator recovery. In the supported single-process deployment, the request barrier remains until restored database migration and listener binding complete. Provider inventory and reconciliation are persisted durably and retried idempotently; provider failure does not roll back an external system transaction because no distributed transaction exists. Whole restore is not an atomic cross-domain switch, and portable power-loss atomicity is not claimed. Live S3/Google interoperability remains unverified. See [the transaction boundary](../backup-restore-transaction-boundary.md) and [BACKUP.md](../../BACKUP.md).

## Live GitHub state at query time

At the query after PR #142 merged, open PRs were:

| PR | Head | Base | State | Remaining reason |
|---|---|---|---|---|
| [#95](https://github.com/bielxdh3/Root.ark/pull/95) | `95d99e4a934384fcfa2101dfc210741cd791a3d1` | `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1` | Open, `DIRTY`; listed checks from 2026-10-01; four review threads resolved. | Issue #94 still requires deployment-wide/shared enforcement or verified single-process topology. Rebase/current-base checks remain necessary. |
| [#97](https://github.com/bielxdh3/Root.ark/pull/97) | `a6a33a92cd6902f303254e60031da4bdc04cec04` | `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1` | Open, `CLEAN`; listed checks from 2026-10-01; five review threads resolved. | Selective network transfer, native Files On-Demand, external-writer-safe eviction, and deterministic restart/reconnect acceptance remain incomplete. |

Open issues at the same query: #63 protected search; #64 native Android; #65 Zero-Knowledge runtime; #66 selective sync / Files On-Demand; #67 destructive-change protection; #68 operation-scoped capability sharing; and #94 deployment-wide chunk-upload rate limiting. Keep all open until their actual acceptance criteria are met. The moderate `sprintf-js` Dependabot alert `GHSA-hp3w-g68c-fv3c` was also still open, with no first patched version listed.

## Security and deployment boundary

The merged corrections include fail-closed production bootstrap, explicit trusted-proxy configuration, non-safe methods for state changes with CSRF enforcement, logout session revocation, default-branch workflow triggers, and dialog focus containment. These repository controls do not prove a live proxy/TLS/provider topology. Root.ark remains not production-ready and must not be described as runtime Zero-Knowledge. Local/process rate limits still do not satisfy Issue #94's deployment-wide criterion. Search remains incomplete, the native client is not implemented, selective sync is partial, backups/history do not implement ransomware recovery barriers, and existing bearer shares are not operation-scoped capabilities.

## Documentation alignment

The following current source documents were checked against the implementation and the exact-SHA evidence above: [development setup and proxy configuration](../development-setup.md), [browser session threat model](../security/browser-session-threat-model.md), [current security findings](../security/current-findings.md), [restore transaction boundary](../backup-restore-transaction-boundary.md), [backup/restore operator guide](../../BACKUP.md), and the Security Regression, CodeQL, and Dependency Review workflow triggers. The Phase 15 local report is a historical phase record and is labeled as such. Current issue/PR state is captured above; later snapshots must be re-queried rather than copied forward as live state.
