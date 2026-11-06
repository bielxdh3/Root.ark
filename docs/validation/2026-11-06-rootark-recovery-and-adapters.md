# Recovery and cloud-adapter verification — 2026-11-06

Status: **BOUNDED LOCAL VERIFICATION**. This is evidence of disposable local tests, **not** production, external provider, key-custody, or ZK-1 cutover certification. No deployment, merge, migration, or secret-bearing provider requests were performed for this checkpoint.

## Source and execution environment

- Source baseline: `Root/main` `ea0445df8ccd8f17da2c70572786d298491fd2c2` (#250). The independent draft PR #253 (`5afe47dceaad3cb29f09406aa306c67127f801e8`) adds read-only `/sync/v1/objects/:objectId/history` and one test. PR #252 (`9d72a7114ce235e87e9fcb98a786229129c731e3`) supplies the first-wave deployment profile.
- Environment: Windows 10; local Node.js **24.14.1**; isolated `E:\servidor\.worktrees\rootark-issue67-history-20261105` plus disposable fixtures. Reused the existing E: `node_modules` through a local, untracked junction; **no dependency version changes**, no real external credentials. The first backup-cloud attempt failed 10 subtests because test subprocesses resolved absent absolute `node_modules/{unzipper,better-sqlite3}` paths. After the fixture dependency path was made available, all 28 subtests passed; do **not** count the initial environment error as a product regression.

## Reproducible local verification

| Suite / gate | Results | Scope proved |
| --- | --- | --- |
| `node --test test/issue-67-sync-burst-guard.test.js` on PR #253 | **39 pass, 0 fail, 0 skip** | History remains available after a logical delete, tenant isolation, `listFiles` denial, ciphertext-only response, persisted destructive-burst pause, resume, TOTP/recovery replay and bounded pruning; new history route had a real RED (404) before implementation |
| `node --test test/backup-cloud-completeness.test.js` | **28 pass, 0 fail, 0 skip** | Fake local/S3/Drive storage, cloud-only files, SQLite backup/restore, inventory failure, rejected unsafe names and cloud-object scoping |
| `node --test test/backup-restore-transaction-boundary.test.js` | **125 pass, 0 fail, 6 skip** | Whole-restore preimages, JSON/SQLite consistency, crash/restart and rollback boundaries, fail-closed provider reconciliation, quarantine journals and object authority |
| `node --test test/cloud-storage.test.js test/issue-65-full-multiprovider-http-restore.test.js` | **64 pass, 0 fail, 1 skip** | Local/S3/Drive adapter behavior, key and parent scope, bad-source cleanup, exact provider identity/version pins, and client-side quorum restore using S3 SDK, Drive HTTPS and WebDAV mTLS fixtures |
| Hosted PR #253 | **Ubuntu Node 22, Windows Node 22 canonical and mandatory gates, CodeQL, dependency review, PG18, Kotlin and provider/Android focused jobs: PASS** | Hosted multi-platform gates for exact PR #253 SHA; do not transfer these results to a different future HEAD |
| Hosted PR #252 | **Ubuntu Node 22, Windows Node 22 canonical and mandatory gates, CodeQL, dependency review: PASS** | Hosted first-wave fail-closed rate-store configuration/profile gate for exact PR #252 SHA |

Six Windows skips in the transaction-boundary suite are platform-specific: POSIX FIFO/symlink/hardlink facilities or directory-fsync behavior not available in that host configuration. The provider suite's single skip covers a POSIX-only public temporary-directory ancestry test. These are **not** counted as passes. Hosted Ubuntu checks above supply independent Linux regression coverage, but not a real cloud restore drill.

## Real acceptance boundaries (R3/R5 → R1)

- **R3 — bounded local recovery evidence is verified.** All tested fake-provider and crash/restore cases passed; an actual encrypted backup export and restore in an operator-controlled nonproduction environment remains a separate operational acceptance before deployment.
- **R5 — provider adapter source-level review and simulated tests only.** The local, S3, Google Drive and WebDAV code paths are under test, including failure, provider-identity switching and signed catalog quorum. Independently inspect code/review findings and confirm *which* configured providers the owner will actually use. Network transport, provider durability/consistency, live credentials, DNS/TLS and service permissions cannot be certified through fake adapters.
- **R1 — NOT DONE.** Requires trusted external key-custody attestations, physical/provider durability evidence, deployment/ingress configuration and an independently authorized ZK-1 cutover; none were performed. The project's default-off protected ZK mode must not be silently enabled.
- **#67 — NOT CLOSED.** The bounded Sync v1 history endpoint makes retained ciphertext recoverable by authorized clients but is not off-host immutable snapshots, a client restore UI, or a full ransomware response/recovery acceptance.

The pragmatic next action is to record the independent R5 review, resolve only real findings, then select an authorized disposable external-transport/restore acceptance profile before any release recommendation. Avoid adding distributed infrastructure or speculative threat scenarios not part of the supported single-instance architecture.
