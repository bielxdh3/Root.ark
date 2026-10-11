# Root.ark closure snapshot — 2026-10-11

**Status: PARTIAL.** The merged security corrections and broad disposable-browser work are recorded below. The final documentation candidate still requires exact-head CI, merge, validation of the resulting exact Root/main SHA, and a fresh independent review. The repository-wide Codex Security Deep Scan could not start because this runtime did not provide the managed filesystem permission profile required by its read-only worker; no scan result is claimed.

## Source and GitHub snapshot

- Mission baseline: 1df5e4640d4aea7dc700f2088059f489c2e51af0.
- Live default branch at the prepublication query: Root/main SHA b3a8aff4c218d4fa522c22a4c12d1f2bbd5f3cd8. The validation checkout was clean and exactly matched this SHA.
- Application source SHA: e0cf2f59b5a51594ed5d744d18d2829bb07db51b. PR #160 changed documentation only and merged at b3a8aff4c218d4fa522c22a4c12d1f2bbd5f3cd8.
- PR #161, fix(ui): preserve workspace state during uploads, merged from ac1372aa2fa241e622604b40ed1a98a88e2d0927 at c402ec16219b68cbe5fd425f863a63182d56d94a.
- PR #162, fix(auth): anonymize unauthenticated failure audit actors, merged from 711593c6e5fbd85a35887ae82a758dd5bdb612e3 at e0cf2f59b5a51594ed5d744d18d2829bb07db51b.
- PR #160, docs: reconcile post-162 closure status, merged from 7be788bf6d7fd9bbd77f4267fc0a54e5c5811f8e at b3a8aff4c218d4fa522c22a4c12d1f2bbd5f3cd8.
- Open issues: #63–#68 and #94. Their acceptance criteria remain incomplete.
- Open PRs at the query: #95 and #97 only. Both target stale base d2ae0eb1c2fc87c1131a73c2a324c695b71664c1. PR #95 is DIRTY; PR #97 is CLEAN. Their successful checks date from 2026-10-01, not the current base. All four review threads on #95 and all five on #97 are resolved. Neither stale head is ready to merge without a fresh-base review and current exact-head checks.
- Dependabot alert #1 remains open at medium severity for GHSA-hp3w-g68c-fv3c in sprintf-js; GitHub reports no first patched version.
- This is a point-in-time prepublication snapshot. It does not predict the documentation PR number or merge SHA. Check GitHub for later PR, issue, and check state.

## Corrections and regression evidence

| Boundary | Merged evidence and status |
|---|---|
| Bootstrap credentials | Fresh install, secure seed, development/test, and production/deployment behaviors are covered by merged regressions. Production-capable startup fails closed unless explicit secure initialization is configured. |
| State-changing GET and CSRF | Reviewed mutations use non-safe methods; browser calls use those methods; legacy GET mutation paths are rejected. Cookie-authenticated state changes keep CSRF and origin checks. |
| Trusted proxy and client IP | TRUSTED_PROXIES explicitly gates forwarded-header use. Auth, rate limits, audit identity, WebSocket origin handling, and origin-sensitive share behavior use the trusted-peer chain. Direct-origin spoofed forwarding headers are ignored. Deployment hop order, header replacement, and origin isolation remain operator-specific and unverified here. |
| Login/TOTP audit | PR #162 records failed unauthenticated events with actor anonymous, keeps attempted identities separate, avoids credential/challenge material, and bounds challenge-failure audit writes. Focused auth/TOTP tests passed 12/12 on the exact PR head. |
| Default-branch CI | Security Regression runs on push to Root/main as well as pull requests. The exact b3 merge SHA received its own push-triggered workflow run; PR-head results were not substituted. |
| Roadmap and issue ledger | PR #160 reconciled the post-#162 state. This follow-up snapshot records the subsequent live b3 publication boundary while preserving prior dated snapshots as history. |

An independent final review of the exact b3 source and prior published correction set reported no actionable finding at that time. A fresh review of the final documentation candidate and its resulting default-branch SHA remains required.

## Exact-SHA validation

| Check | Exact SHA | Result |
|---|---|---|
| npm run validate:release-gate | b3a8aff4c218d4fa522c22a4c12d1f2bbd5f3cd8, clean detached checkout | 21 passed, 0 blocked, 0 failed |
| Canonical npm test | b3a8aff4c218d4fa522c22a4c12d1f2bbd5f3cd8 | Passed as part of the exact-source validation |
| Security Regression, run 38131294264 | b3a8aff4c218d4fa522c22a4c12d1f2bbd5f3cd8 | Ubuntu Node 22: 1,140 passed, 11 skipped, 0 failed. Windows Node 22: 1,136 passed, 15 skipped, 0 failed. Syntax validation, runtime-artifact guard, and configured high-severity dependency audit passed where supported. |
| CodeQL, run 38131294305 | b3a8aff4c218d4fa522c22a4c12d1f2bbd5f3cd8 | Passed |
| Default-branch Dependency Review, run 38131294272 | b3a8aff4c218d4fa522c22a4c12d1f2bbd5f3cd8 | Passed |
| Pages, run 38131294251 | b3a8aff4c218d4fa522c22a4c12d1f2bbd5f3cd8 | Passed |

The documentation candidate and its eventual merge SHA require their own validations. None of the b3 checks establishes the candidate or future merged documentation SHA.

## Browser and UI acceptance

Real-browser checks used disposable local runtimes and synthetic accounts/files, not user data. The broad UI matrix recorded in [the post-#162 snapshot](2026-10-11-rootark-post-162.md) ran on PR #161's application tree, which matches the merged `c402ec1` tree for the changed files. It covered login and 2FA enrollment/login; files and folders; normal and 9 MiB chunk upload; encryption/expiry controls; upload failure/retry and preserving settings after drop; approve/reject; preview/download; share/password flows; versions, rename, move, permissions, expiry, trash/restore/permanent deletion of an agent-created fixture; users/groups; quarantine; audit/CSV export; backup creation, manifest, and restore confirmation; errors/denials; and compact navigation. It did not claim a full restore or restart-recovery test.

A separate login/workspace/responsive-navigation smoke on application SHA `e0cf2f59b5a51594ed5d744d18d2829bb07db51b` is documented in that same snapshot; it was not a repeat of the broad matrix. In this closure run, a separate disposable browser session on the b3 application tree completed the TOTP challenge with a valid code and rejected an invalid code. The broad-matrix viewports and keyboard/focus/dialog checks are attributed to the `c402ec1` run; the `e0cf2f5` smoke checked 1440×900, 768×900, and 390×844 workspace widths and mobile navigation.

Quarantine ingestion was separately exercised on the b3 application tree with a benign disposable file and an isolated loopback fake ClamAV service that deliberately returned an infected result. The normal browser upload flow displayed the security-blocked status and retained the selection; the server emitted `upload.scan.infected`; the admin quarantine table showed the item with reason `clamav_infected` and the expected 75-byte size. This verifies the app's route, UI, and ClamAV protocol-handling path, not a real ClamAV engine or virus signature. The quarantined fixture remains only in the disposable test runtime; its permanent-delete action was not used in this run. No live S3/Google provider interaction was exercised. The tests were operator-observed; a full browser screenshot of the admin quarantine row was captured during validation, but per-flow screenshots and a reusable browser trace were not retained. The isolated 2FA runtime was stopped after use, but local cleanup of its test-only runtime files was blocked by the workspace operation guard; no such files are in the repository.

The full disposable restore followed by server restart and the expired-session 401/redirect are documented against the older exact `Root/main` SHA `ad4707037933ee9a65a53e76a26ae3b1cea01160` in [the 2026-10-08 historical snapshot](2026-10-08-rootark-mission-closure.md). They are historical evidence, not acceptance evidence for `e0cf2f5` or b3.

## Restore transaction semantics

Restore validates the archive, paths, quarantine state, provider inventory, and request quiescence before local mutation. A durable coordinator and verified pre-images cover locally controlled quarantine, JSON/data, uploads, SQLite files and sidecars, and restore-derived provider policy. Local stages apply sequentially; failures before the durable `restart_required` local-commit boundary trigger reverse-order compensation to verified pre-images. After that boundary, restored local state remains authoritative: migration and provider-reconciliation failures keep the durable barrier/coordinator in place and retry forward on restart rather than rolling back to pre-restore state.

Restore is not globally atomic across stores or cloud APIs. External provider effects cannot join a portable filesystem/SQLite transaction, external writers can bypass the app barrier, and Node.js does not provide portable Windows directory-entry fsync. Missing/corrupt pre-images, permission loss, or persistent storage failure can require operator-assisted recovery. Live cloud interoperability was not demonstrated. See the detailed [whole-restore transaction boundary](../backup-restore-transaction-boundary.md).

## Remaining work and closure boundary

- Issue #63: protected search still lacks the complete protected index/encrypted lifecycle, privacy and metadata-leakage acceptance, UI integration, and approved FTS/search behavior.
- Issue #64: architecture is not a functioning native Android client.
- Issue #65: protocol primitives do not establish an end-to-end Zero-Knowledge runtime across upload, download, preview, scan, sync, WebDAV, backup, restore, sharing, migration, and recovery.
- Issue #66 / PR #97: metadata-only paginated remote catalog, selective network transfer, native Files On-Demand, external-writer-safe eviction, and deterministic crash/reconnect behavior remain incomplete.
- Issue #67: burst/destructive-change detection, pause/review, protected history, recovery authorization, and adversarial recovery UX remain incomplete.
- Issue #68: legacy bearer links do not implement operation-scoped least-privilege capabilities.
- Issue #94 / PR #95: current process-local limits and local staging do not prove deployment-wide enforcement or a verified single-process topology.
- Whole restore remains bounded local rollback/restart recovery plus durable provider reconciliation, not full cross-domain atomicity.
- Deployed proxy topology, direct-origin isolation, Cloudflare source/header controls, and live cloud provider behavior remain unverified.
- Real ClamAV-engine interoperability and quarantine approve/reject actions were not tested; quarantine ingestion was validated only against the disposable fake protocol service described above.
- The repository-wide Codex Security Deep Scan is BLOCKED_ENVIRONMENT because its required managed filesystem profile was unavailable. The scan did not start and no result is claimed.
- Root.ark is not production-ready and is not an end-to-end Zero-Knowledge runtime.

The final exact default-branch SHA, its Security Regression/Windows/Linux/CodeQL/dependency results, and a fresh independent review must be recorded by the final mission report after publication.
