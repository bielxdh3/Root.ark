# Root.ark final closure snapshot — after PR #129

## Scope and timestamp

This is a point-in-time record queried on 2026-10-08 after PR #129 merged. At that query, the canonical `Root/main` SHA was `f543f0f4045d12ecbaf6f8b793d3d24aecb98e25`. It preserves the post-#127 issue ledger and closure report as historical evidence. Re-query GitHub before treating any issue, PR, alert, review, or check state here as live after this snapshot.

## Merged closure corrections and exact-SHA checks

- PR #128 merged at `6d89b55641f393fcce6026ead24d1f53bfeb227c`.
- PR #129, `fix(ci): classify missing local modules as release gate failures`, merged from head `e421dd9e2abfc689b2d645e05e0e6f0a86e260d4` at `f543f0f4045d12ecbaf6f8b793d3d24aecb98e25`.
- On that exact `Root/main` SHA, Security Regression [run #37802102581](https://github.com/bielxdh3/Root.ark/actions/runs/37802102581) passed: Ubuntu ran 990 tests (979 passed, 11 skipped, 0 failed); Windows ran 990 tests (986 passed, 4 skipped, 0 failed). CodeQL [run #37802102885](https://github.com/bielxdh3/Root.ark/actions/runs/37802102885), default-branch Dependency Review [run #37802102747](https://github.com/bielxdh3/Root.ark/actions/runs/37802102747), and Pages [run #37802100648](https://github.com/bielxdh3/Root.ark/actions/runs/37802100648) passed.
- `npm run validate:release-gate` on the clean checkout at this SHA reported 21 passed, 0 blocked, and 0 failed. This run predates the follow-up correction described below and does not validate that later patch.

## Live GitHub state at this query

- Open PRs: #95 `Rate-limit chunk uploads before Multer` (head `95d99e4a934384fcfa2101dfc210741cd791a3d1`, base `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1`, `DIRTY`) and #97 `Add guarded selective sync core` (head `a6a33a92cd6902f303254e60031da4bdc04cec04`, same stale base, `CLEAN`). Their listed checks are from 2026-10-01, before the current base. All four threads on #95 and all five on #97 were resolved. #95 remains open because deployment-wide chunk-upload limits or single-process topology are unverified; #97 remains open because selective transfer, paginated metadata-only listing, a native Files On-Demand provider, and safe cache eviction/restart semantics remain incomplete.
- Open issues: #63 protected search, #64 native Android, #65 Zero-Knowledge runtime, #66 selective sync / Files On-Demand, #67 destructive-change protection, #68 capability-based sharing, and #94 deployment-wide chunk-upload rate limits.
- Dependabot alert #1 remains open at moderate severity for `sprintf-js` (`GHSA-hp3w-g68c-fv3c`); GitHub lists no first patched version.

## Findings from the post-merge review

A fresh scoped review of the exact post-#129 SHA found two follow-up items. First, the release-gate helper treated any unresolved bare external import as an environment block, including a misspelled or undeclared package; this could misattribute a source/dependency error as `BLOCKED`. Second, the canonical plan and ledger had not yet pointed to a post-#129 state record. The latter is addressed by this snapshot and its plan/ledger links. The classifier issue is addressed in a separate follow-up patch with tests that distinguish missing declared packages from unknown imports, including mixed network and import diagnostics. That follow-up must pass its own exact-head and post-merge checks before it can be called complete.

The scoped reviews of authentication, session/TOTP, CSRF and mutation methods, trusted-proxy identity, WebSocket/public-share Origin handling, restore recovery, SQLite rollback, and provider reconciliation reported no actionable finding in those reviewed areas. Whole restore remains locally rollback-recoverable, not globally atomic: local stages are compensated and recovered after restart, while cloud-provider operations remain durable idempotent reconciliation work. Process interruptions are covered by disposable failure-injection tests; provider interoperability with live services and portable power-loss atomicity are not claimed.

## Browser acceptance and remaining boundaries

The disposable-fixture browser record is in [the post-#127 closure report](2026-10-08-rootark-mission-closure.md). It covers login/TOTP, files and folders, uploads and injected chunk failure, approvals, sharing/password access, preview/download, versions, ACLs, trash/restore/delete, backup/manifest/restore/restart, audit export, and desktop/tablet/mobile navigation and keyboard behavior. Acceptance remains partial: quarantine mutation was not exercised; actual expiration, active session revocation, and dirty-form preservation during a real realtime refresh were not verified; per-flow screenshots and a machine trace were not retained. No complete browser acceptance claim is made.

Protected search, Android, end-to-end Zero-Knowledge runtime, full selective sync/Files On-Demand, ransomware protection, capability-based sharing, and deployment-wide chunk-upload enforcement remain open. No production-readiness or full restore atomicity claim is made.

## Mission status at this snapshot

`PARTIAL`. Exact post-#129 CI and the local release gate passed, but the release-gate classifier follow-up, full browser acceptance, and a fresh independent final review of the eventual final `Root/main` SHA remained pending at this snapshot. The post-#127 issue ledger and closure report remain historical records.
