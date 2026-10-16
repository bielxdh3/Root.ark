# Root.ark closure validation snapshot — 2026-10-16

This is a point-in-time snapshot queried after PR #199 merged and before the closure documentation publication. It is not final-SHA evidence for the documentation PR or its merge.

## Repository and GitHub state

- Canonical branch: `Root/main`
- Exact application SHA at query: `18d45696e9c07d706de1e9ab161d1b642cbd3d87`
- No open PRs at query. Mission PRs #195–#200 are merged; exact merge SHAs are listed in the [issue ledger](../issue-ledger.md).
- Open issues: #63 protected search, #64 native Android, #65 Zero-Knowledge runtime, #66 selective sync / Files On-Demand, #67 destructive-change protection, #68 capability sharing, #94 deployment-wide chunk-upload limits, and #186 aggregate chunk-staging limits.
- PR #199 and PR #200 had no unresolved review threads at query. Their GitHub check and local validation evidence is below.

## Exact-head validation

| Commit | Platform and command | Result |
|---|---|---|
| PR #200 head `59165d4ccf3cfb1f618b1ec5ff98fd5b6a7e0df6` | Windows, `npm run validate:release-gate` on a clean immutable checkout | 21 passed, 0 blocked, 0 failed. The gate included the full `npm test`, high-severity dependency audit, syntax checks, runtime-artifact and secret guards. |
| PR #200 head | Windows, focused `node --test` for `test/fs-atomic-rename.test.js`, `test/realtime-transport-boundaries.test.js`, and `test/realtime-webdav-crash-consistency.test.js` | 4/4, 14/14, and 15/15 passed, respectively. |
| PR #199 head `0db94c2a00aa61f6cbbf3c8e9c7dbf77caa9b77e` | Windows, `npm run validate:release-gate` on a clean immutable checkout | 21 passed, 0 blocked, 0 failed. The gate included the full `npm test`, high-severity dependency audit, syntax checks, runtime-artifact and secret guards. |

On both PR heads, GitHub CodeQL, Dependency Review, and Ubuntu full validation succeeded. The GitHub Windows validation jobs were cancelled; the exact-head local Windows gates above passed. These statements distinguish remote results from local execution and do not transfer to another SHA.

At query time for default-branch SHA `18d45696e9c07d706de1e9ab161d1b642cbd3d87`, GitHub Dependency Review and CodeQL had succeeded and Security Regression was still in progress. The local release gate for this default-branch SHA and all checks for the post-documentation final SHA were pending.

## Corrected boundaries represented by the merged work

- PR #199 strengthens quota coverage for maximum-size multipart assembly while source parts remain charged.
- PR #200 uses the shared Windows-only transient `EPERM` rename retry for WebDAV MOVE journal and metadata replacement. The implementation does not unlink the previous destination or substitute a non-atomic copy fallback.
- PR #192 implements operator-supplied positive byte and entry limits through a separate local SQLite ledger. Chunk uploads fail closed unless the limits and supported single-host/shared-local-volume topology are configured. Multi-host, NFS, SMB, and unverified storage remain unsupported; the project does not choose deployment capacity values.
- PR #97 is merged selective-sync foundation work. Its tombstone regression covers an offline move outside selected paths followed by remote deletion, preserving dirty local data and pending operations by the existing conflict policy. Issue #66 remains open because its full acceptance criteria are not met.

## Restore and release limitations

Whole restore uses local preimages, a durable coordinator, rollback compensation, restart recovery, and durable provider reconciliation. It is not an instantaneous atomic switch across quarantine, filesystem, JSON/SQLite, and external cloud APIs. Provider effects and external writers remain outside the local rollback transaction. Do not describe this as fully atomic or claim live provider interoperability.

Protected search, native Android, end-to-end Zero-Knowledge runtime, full Files On-Demand/selective sync, ransomware protection, operation-scoped capability sharing, and deployment-wide chunk-upload limiting remain open. Dependabot alert #1 for `GHSA-hp3w-g68c-fv3c` remained open at medium severity at query.

No full mission-wide browser acceptance matrix is claimed by this snapshot. The UI was not changed by PRs #199 and #200; browser acceptance remains a separate closure gate.
