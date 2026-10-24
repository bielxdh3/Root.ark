# Issue #65: POSIX private SQLite bootstrap and Ubuntu CI regression

Development evidence recorded on 2026-10-23 for PR #228. These checks are
SHA-specific, not a statement that the complete PR has passed all CI jobs.

## Published regression: `ea86d3742008a2820c75c9b287c07b4bc47568cb`

- GitHub Actions Ubuntu Node22 full validation: run `39910218522`, job
  `120271234570`: **2,213 PASS, 1 FAIL, 137 SKIP, 0 CANCEL**. The sole failing
  subtest was `external opaque catalog CAS: real mTLS processes, atomic
  competition, signer proof, replay, restart, uncertain ACK and rollback`
  (`test/issue-65-opaque-cas-real-multiprocess.test.js`). It reported
  `ZK_OPAQUE_CAS_UNAVAILABLE` from the disposable child process.
- Node22 real disposable PostgreSQL 18 gate: **PASS** on the same published
  commit. JavaScript/TypeScript analysis and dependency review: **PASS**.
- Hosted Windows Node22 release gate had not reached a conclusive verdict at
  the time of this investigation. CodeQL was still **FAIL**. Neither is a PASS.

## Failure boundary and code change

`Zk1OpaqueCatalogCasLedger` already rejects POSIX SQLite paths that are
readable by another Unix user or group. SQLite's default creation mode,
however, can inherit a typical `022` umask, producing `0644` when a new CAS
database is created directly by `better-sqlite3`. The strict restart check
then rejects the same application's new database. Windows does not enforce
the analogous POSIX mode check and its focused tests passed.

Commit `db7baa6` changes the first bootstrap to create the SQLite file with
`O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW` (where supported) and explicit mode
`0600` **before** opening it with `better-sqlite3` using
`fileMustExist: true`. It remains fail-closed on preexisting/symlink paths or
concurrent bootstrap. The disposable multiprocess test now also asserts that
the newly created database has no group/other permission bits on POSIX.

## Evidence and what is not yet established

- Local Windows Node24 selected mTLS CAS + owner V2 signer rotation:
  **2 PASS, 0 FAIL** after the patch.
- Local Windows Node22 isolated CAS multiprocess suite:
  **1 PASS, 0 FAIL** after the patch.
- `node --check` and `git diff --check`: **PASS** for the patch.
- Linux success of the **patched** SHA remains subject to a fresh Ubuntu CI
  run; earlier `ea86d37` results must not be reassigned to later commits.
- This repair is a POSIX file-mode and restart correctness fix, not evidence
  of remote cloud durability or independently operated machines.

The new independent catalog floor's *own* SQLite bootstrap requires the same
private POSIX invariant and separate regression coverage before it can be
counted as integrated. Likewise owner V2 signer A-to-B rotation must not be
blocked by a static old device signing key at that independent floor.
