# Issue #65: opt-in legacy V2 #129 migration durability (DEV only)

`Zk1OpaqueCheckpointV2Client.migrateLegacy129()` verifies the immutable old
SQLite schema and owner-signed #129 intent on a private read-only database/WAL
snapshot, requires the owner's current witnessed signing authority and both
independently signed FINALIZED CAS/FLOOR heads, then publishes a distinct new
successor-capable journal. It does **not** upgrade, unlink or rewrite the old
journal or its historical `-wal`, `-shm`, `-journal` sidecars.

On a private POSIX directory that supports actual directory `fsync`, a new
staging file is flushed and its parent directory synced before publication.
`link(staged, destination)` is an atomic no-replace operation within the same
directory. The parent is synced again after LINK and again after UNLINK of the
stage. Successful migration is only reported after those barriers and a fresh
verified client reopen. Failure attempts exact-inode destination rollback,
followed by parent-directory `fsync`; unknown/swapped destination identities
are preserved for manual recovery rather than blindly removed.

**Windows limitation:** Node's `fs.fsyncSync()` on a directory descriptor
returns `EPERM` on the observed Windows runtime. Migration performs an early
real parent-directory fsync capability probe and **fails closed**, leaving the
old journal usable and the new destination absent. No file-only sync, synthetic
test callback, or successful Windows filesystem flush of a *file* is treated as
proof of directory-entry durability. Windows native journal migration requires
a separately reviewed and tested durable namespace implementation.

`withReadonlySqliteSnapshot()` now opens the main DB and optional WAL by
descriptor, copies bounded bytes, and rechecks file identity, link count,
size, mtime and ctime through inspection, including WAL presence. A live WAL
write while the snapshot is being checked invalidates the result. This
reduces race exposure but does **not** make SQLite WAL and its source directory
atomically immutable or prove immunity to a privileged same-host actor.

Tests: `test/issue-65-opaque-checkpoint-v2-migration-durability.test.js`
injects LINK, directory barrier and post-reopen failures, verifies failed
publication rollback, and preserves old journal and sidecar bytes; POSIX
barriers are also run on Linux rather than only simulated. The V2 real mTLS
E2E verifies refusal on Windows, including no destination creation. The WAL
race test reproduces a real concurrent WAL append, first RED under the old
guard and then fail-closed GREEN.

Crash/fault injection establishes control-flow safety, not physical power-cut
durability. No independent monotonic storage, multi-host failover, external
provider durability, or production cutover is demonstrated: **NO-GO**.
