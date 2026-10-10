# Root.ark current validation and GitHub snapshot — 2026-10-10

## Verdict and scope

**Status at this code milestone: PARTIAL.** The application-code state recorded here is exact `Root/main` SHA `6d4548808bf7090fc0ae13b238ab6cf948f67d5a`. The mission baseline is `1df5e4640d4aea7dc700f2088059f489c2e51af0`; the live branch before PR #147 merged was `a6bfefc93c545ecc40ec5129206a2695fed2713a`. This is a dated source-code and GitHub snapshot. The documentation-only reconciliation has its own commit and exact-SHA checks, which are recorded in the final engineering report rather than this pre-documentation code snapshot.

The supported restore path now has a durable, restart-recoverable local commit boundary and idempotent, durable provider reconciliation. It is not a simultaneous atomic switch across quarantine, files, JSON/SQLite, and cloud providers. Provider interoperability, deployed proxy/provider topology, and a real-browser quarantine-ingestion flow are not proven here.

## Published work

| PR | Change | Head SHA | Merge SHA |
|---|---|---|---|
| [#147](https://github.com/bielxdh3/Root.ark/pull/147) | Durable backup-history mutations and restore/provider sync recovery | `26f93ef186649d97a796da6175fdb1b88766a818` | `46fa8988eaf74a5d4257c4d7a75e5acde92b1918` |
| [#148](https://github.com/bielxdh3/Root.ark/pull/148) | Concurrency-safe fake WebDAV provider call log | `f8bca56c91e7d71fb8c51f39b7fcb91723c3c254` | `6d4548808bf7090fc0ae13b238ab6cf948f67d5a` |

The correction series also includes the already-merged authentication/CSRF/proxy boundary (#101), default-branch push validation (#103), bootstrap and cloud/restore hardening (#114), restore recovery and migration coverage (#104, #110, #111, #118, #123, #127, #132, #136, #145), state-changing GET/security work (#139), and upload policy hardening (#146). These commits do not establish production deployment topology or external provider interoperability.

## Findings and regression evidence

| Finding | Correction and regression evidence | Status |
|---|---|---|
| Predictable bootstrap credentials | Production startup rejects persisted default development credentials. Defaults are available only through explicit development/test opt-in. Clean-install, seed, environment, and production behavior have regression coverage in the merged security series. | Corrected; production deployment still needs operator-provided configuration. |
| State-changing GET and CSRF bypass boundary | State mutations use non-safe HTTP methods, browser calls were updated, cookie-authenticated mutations retain CSRF/Origin validation, and legacy GET access does not mutate. Cross-site navigation and route behavior are covered by the merged security regressions. | Corrected in supported routes. |
| Forwarded client-IP trust | Forwarding data is used only through an explicit trusted-proxy allow-list; direct untrusted origin headers do not define auth/audit/rate-limit/WebSocket identity. Proxy-hop and direct-origin regressions are in the merged security series. | Corrected in code; live ingress and Cloudflare/origin restriction remain deployment evidence gaps. |
| Main-branch validation gap | Push validation runs on `Root/main` in addition to pull-request validation. The exact merge SHA `6d45488…` received a push-triggered Security Regression, CodeQL, and default-branch Dependency Review run; final status is recorded below. | Workflow correction merged; final post-documentation SHA remains a separate gate. |
| Restore partial-commit boundary | Verified preimages and a durable coordinator cover quarantine, restorable files, uploads, SQLite, and local provider policy. Startup verifies and rolls back interrupted local commits in reverse order; provider work is durable, retryable, and idempotent after local commit. Failure-injection/restart coverage uses disposable fixtures. | Locally rollback-recoverable with an accepted technical boundary; not globally atomic. |
| Concurrent fake-provider test log | Two restart workers could rewrite a shared JSON log while the parent parsed it. PR #148 writes each event to a unique temporary file and atomically publishes a complete per-call record; consumers do not depend on call order. `test/realtime-webdav-crash-consistency.test.js`: 9/9 passed on the PR head. | Corrected; exact merged-SHA CI is recorded below. |
| Roadmap/GitHub drift | The current ledger and plan snapshot below are reconciled to the live issue, PR, alert, and check state queried after PR #148. Earlier dated entries remain historical. | Reconciled at this code milestone. |

## Exact-head validation

### PR #148 head `f8bca56c91e7d71fb8c51f39b7fcb91723c3c254`

| Check | Result |
|---|---|
| Security Regression, [run #38074633338](https://github.com/bielxdh3/Root.ark/actions/runs/38074633338) | Ubuntu Node 22: 1,130 tests, 1,119 passed, 11 skipped, 0 failed. Windows Node 22: 1,130 tests, 1,115 passed, 15 skipped, 0 failed. |
| CodeQL and JavaScript/TypeScript analysis | Passed. |
| Dependency Review | Passed; the default-branch-only job was skipped on the PR event. |
| Local `npm run validate:release-gate` | Final run: 21 passed, 0 blocked, 0 failed on Windows Node 24.14.1/npm 11.11.0. The first attempt reported one Phase 12 exit; two focused Phase 12 runs then passed 9/9 each, and the complete retry passed. |
| `git diff --check` | Passed. |
| Fresh independent review of the PR diff | No actionable finding; reviewer inspected the unique-file publication and collector semantics. |
| Review threads | PR #148 had no review threads at the live query. |

PR #147 head `26f93ef…` had passing Linux/Windows Security Regression, CodeQL, Dependency Review, and a 21/0 local release gate. The browser acceptance below also ran against its application tree. On the merged #147 SHA `46fa898…`, the push Security Regression [run #38073815866](https://github.com/bielxdh3/Root.ark/actions/runs/38073815866) failed on Ubuntu with a race in the fake provider's shared call-log fixture (1,117 passed, 11 skipped, 2 failed); Windows passed (1,115 passed, 15 skipped, 0 failed). PR #148 corrected that test harness race. CodeQL [run #38073815893](https://github.com/bielxdh3/Root.ark/actions/runs/38073815893) and Dependency Review [run #38073815852](https://github.com/bielxdh3/Root.ark/actions/runs/38073815852) passed on `46fa898…`.

### Merged `Root/main` SHA `6d4548808bf7090fc0ae13b238ab6cf948f67d5a`

| Check | Run | Result at snapshot query |
|---|---|---|
| Security Regression | [#38075513410](https://github.com/bielxdh3/Root.ark/actions/runs/38075513410) | Ubuntu Node 22: 1,130 tests (1,119 passed, 11 skipped, 0 failed). Windows Node 22: 1,130 tests (1,115 passed, 15 skipped, 0 failed). Syntax and runtime-artifact checks passed on both; Ubuntu's configured high-severity dependency audit passed. |
| CodeQL | [#38075513418](https://github.com/bielxdh3/Root.ark/actions/runs/38075513418) | Passed. |
| Default-branch Dependency Review | [#38075513462](https://github.com/bielxdh3/Root.ark/actions/runs/38075513462) | Passed. The existing moderate `sprintf-js` alert remains open. |
| Pages | [#38075513083](https://github.com/bielxdh3/Root.ark/actions/runs/38075513083) | Passed. |

These checks certify only source SHA `6d454…`. The documentation-only PR produces a different Git SHA; the final engineering report must identify that exact post-merge SHA and its own checks. Neither PR-head nor this earlier merge-SHA evidence substitutes for final-SHA validation.

## Browser and UI acceptance

Real Chromium browser validation ran on PR #147's application tree (head `26f93ef…`) at desktop 1440×900, intermediate 768×900, and compact 390×844. PR #148 changed only the test fixture, so it did not change the browser-served code.

Covered flows included login and TOTP enrollment/challenge/replay protection; file list and folder navigation; regular and chunk upload with progress and a controlled 503 retry; encryption and expiry controls; pending approval and rejection; preview/download; password-protected shares; versions; rename/move; file/folder permissions; temporary-folder expiry configuration; trash, restore, and permanent delete; admin users/groups; quarantine empty state; audit/export; backup creation/manifest/restore confirmation and cancel; reader denial; session revocation; and dirty-form preservation during realtime refresh. Requests were checked for method and status where relevant.

Responsive checks found no horizontal overflow at the tested widths. Initial Tab reached the skip link; the tested permission dialog had a programmatic label, focused its close control, and kept Tab navigation inside the dialog. Public text shares did not show Preview; PDF shares did and opened successfully. The corrected public-share tab ended with zero console errors/warnings; expected wrong-password, replay, and injected-503 responses were observed in the broader test session.

Residual browser limits: quarantine ingestion was not proven (only the empty state was visited); folder expiration was set and read back but not allowed to elapse; restore was confirmed and cancelled in the browser rather than applied to user data; no live cloud provider was used. These remain unverified acceptance boundaries, not passes.

## Restore transaction semantics

1. **Stage and validate:** validate archive, manifest, path/quarantine rules, and destinations; persist a coordinator and verified preimages for quarantine, JSON state and backup history, uploads, SQLite files/sidecars, and local provider policy before mutation.
2. **Local mutation:** apply domains in sequence behind the HTTP/background-worker barrier. Failure or interruption after the `prepared` boundary causes startup to verify preimages and restore local domains in reverse order. Missing/corrupt evidence or rollback failure keeps the service unavailable for manual recovery.
3. **Restart boundary:** after local commit, the supported single-process server remains gated until restored database migrations complete and its listener binds. Migration failures before bind retain the coordinator and recovery material; migration transactions roll back their own partial changes, while earlier committed migrations retry forward.
4. **Provider reconciliation:** cloud state cannot join a portable filesystem/SQLite transaction. Durable queues use operation identities, leases, deterministic provider IDs/keys, retry/backoff, and startup recovery. Provider failures keep affected objects unavailable/suppressed until selected bytes reconcile; local restored state remains authoritative.

Residual risk is explicit: local changes are sequential and rollback is compensating, so external writers/processes outside the app barrier can observe or cause intermediate changes. Windows lacks a portable Node.js parent-directory flush, so power-loss durability is weaker there. Cloud-provider atomicity and live interoperability cannot be guaranteed by a local transaction; retries are idempotent, not distributed commit. The transaction and provider tests use disposable fixtures only.

## Live GitHub state at query time

Open issues: #63 protected search; #64 native Android; #65 Zero-Knowledge; #66 selective sync / Files On-Demand; #67 ransomware/destructive-change protection; #68 capability-based sharing; and #94 deployment-wide chunk-upload limits. All remain open because their acceptance criteria are not met.

| Open PR | Head | Base | Checks/review state | Remaining reason |
|---|---|---|---|---|
| [#95](https://github.com/bielxdh3/Root.ark/pull/95) | `95d99e4a934384fcfa2101dfc210741cd791a3d1` | stale `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1` | Checks passed on 2026-10-01, before current base; 4/4 threads resolved. | Issue #94 still lacks verified deployment-wide enforcement or an accepted single-process topology. |
| [#97](https://github.com/bielxdh3/Root.ark/pull/97) | `a6a33a92cd6902f303254e60031da4bdc04cec04` | stale `d2ae0eb1c2fc87c1131a73c2a324c695b71664c1` | Checks passed on 2026-10-01, before current base; 5/5 threads resolved. | Network-selective transfer, native Files On-Demand, external-writer-safe eviction, and deterministic restart/reconnect acceptance remain incomplete. |

PRs #147 and #148 are merged. PR #99 and #100, previously referenced in the mission, were already merged before this snapshot. No unresolved review threads remained on #147 or #148. The one open Dependabot alert is moderate `GHSA-hp3w-g68c-fv3c` / `CVE-2026-97058` in transitive `sprintf-js`; GitHub lists no patched version.

## Security and deployment conclusion

The merged source enforces fail-closed production bootstrap, explicit trusted-proxy configuration, unsafe methods plus CSRF for cookie-authenticated mutations, session freshness/revocation, upload scanner failure handling, public-share owner authorization, WebDAV session/origin checks, and local restore recovery. These code controls do not establish the live TLS/proxy/provider topology. Rate-limit state remains process-local in some flows. Existing bearer links are not operation-scoped capabilities. Search is incomplete, no native Android client exists, destructive-change recovery protection is not implemented, and supported server paths still access plaintext; Root.ark is not an end-to-end Zero-Knowledge runtime and is not production-ready based on repository evidence alone.

## Remaining gates

- The final engineering report must cite the exact post-documentation `Root/main` SHA and its push-triggered Security Regression on Ubuntu and Windows, CodeQL, Dependency Review, Pages where configured, release gate, full tests, artifact/secret checks, and clean checkout. The checks above apply only to `6d454…`.
- The fresh independent final review must use that exact post-documentation SHA, including auth/session/TOTP, CSRF/proxy, mutation routes, upload/storage, backup/restore, sync/WebDAV, sharing/ZK boundaries, CI, docs, and remaining issues/PRs. This dated snapshot predates that review.
- Keep quarantine-ingestion browser proof and folder-expiration-elapse proof explicitly open unless exercised with disposable data.
- Keep issues #63–68 and #94 and incomplete PRs #95/#97 open until their actual acceptance criteria pass.
