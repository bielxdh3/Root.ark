# Root.ark — virtual-tree cross-PR regression evidence

**Date:** 2026-11-06. **Nonproduction only; no merge commits, branch checkout modifications, production data or deploy.** Both source trees were produced with `git merge-tree --write-tree` from published exact draft PR HEADs, exported into new disposable folders on E:, with local junctions to previously installed E: dependencies. `Root/main` and the PR worktrees were not changed.

## Pair A — encrypted history and selective inventory

| Input | Exact SHA |
| --- | --- |
| Draft PR #253 | `5afe47dceaad3cb29f09406aa306c67127f801e8` |
| Draft PR #255 | `3ccf955874271546b61ecac09d77227612d330fe` |
| Resulting virtual tree | `0ce1190e749adb639b1aa102a942a53ac844bad3` |

Windows 10, Node.js v24.14.1, disposable directory `E:\servidor\.worktrees\_scratch-rootark-combined-253-255-20261106`, reused preexisting E: dependencies and safe local TEMP.

- `node --check src/routes/sync.js`: PASS.
- `node --test test/issue-67-sync-burst-guard.test.js test/issue-66-metadata-inventory.test.js test/issue-66-selective-sync.test.js`: **56 PASS / 0 FAIL / 0 SKIP** in 56.429 seconds.
- Includes tenant-isolated paginated metadata, two-tenant bounded caches, external writer invalidation, selected paths, retained ciphertext after logical deletion, pruning, destructive-operation pause, TOTP/recovery-code replay and reauthorization.

## Pair B — safe rate-store configuration and sharing permissions

| Input | Exact SHA |
| --- | --- |
| Draft PR #252 | `909f760e53965a29f6b66b09b09cc7ceebf4dd3f` |
| Draft PR #256 | `e721d67923654bf77eff7bbeea76069c42f29940` |
| Resulting virtual tree | `42e075b9483fb3f90f4db84c60ae0bc21f3f6d96` |

Same Windows/Node host, disposable directory `E:\servidor\.worktrees\_scratch-rootark-combined-252-256-20261106`, with separate export and reused dependency-tree junction.

- `node --check server.js`: PASS.
- `node --test test/issue-94-sqlite-rate-store.test.js test/issue-68-share-permissions.test.js`: **35 PASS / 0 FAIL / 0 SKIP** in 84.052 seconds.
- HTTP test paths include JSON/SQLite link authorization, revoked permissions during in-flight download and preview, already-counted preview, fail-closed invalid rate-store settings and shared SQLite window counts.

## Limits

**91 PASS / 0 FAIL / 0 SKIP for the two virtual pairs.** This evidence does not claim all 11 open PRs were integrated or run as a single hosted artifact. The trees are not branch merges, and full combined hosted CI and external R1 custody/durability remain separate. The GHAS CodeQL app for PR #255 still flags an unchanged baseline helper even though its normal CodeQL Analyze and hosted Security Regression passed; **no suppression or complete-green claim** was made.
