# Whole restore transaction boundary

Whole restore uses a durable, local rollback protocol. It does **not** provide instantaneous atomic visibility across JSON files, quarantine, uploads, SQLite, and cloud providers. Before replacing local state, Root.ark stages and verifies preimages for every locally controlled destination the archive can change. If the process stops before the local commit boundary, startup restores those preimages before migrations or request handling. Cloud-provider effects remain outside that local rollback domain.

## Admission and service barrier

Restore takes the shared backup-operation lock, validates the full staging-root and backup-ID path (including symlink/junction checks), then writes a `preparing` coordinator at `data/.rootark-restore-coordinator.json` and drains active work before creating the pre-restore backup. The HTTP gate runs before body parsing, static files, and routes. Each admitted HTTP request holds a lease in `data/.rootark-active-requests/`. Long-running cloud trash, cloud restore-sync, WebDAV reconciliation, fire-and-forget cloud writes, and cleanup workers use the same gate. A restore waits for their leases. A lease-directory error or bounded quiescence timeout aborts before restore destinations change.

Leases are not removed based on local PID checks because PIDs do not identify the same process in every container or host sharing a volume. A crash may leave a stale lease and make a later restore time out. Stop every instance using the shared runtime, verify that no operation remains active, and remove only confirmed stale lease files as an operator action.

Every process accessing restored files must share the same `data/` and `uploads/` volumes and lease directory. Configure `ROOTARK_RESTORE_INSTANCE_COUNT` to the exact number of application instances and give each instance a stable, unique `ROOTARK_INSTANCE_ID`. A count mismatch, duplicate or missing ID, or instance that fails to start keeps the restore barrier active.

The shared operation lock uses exclusive file creation and records its owner instance ID. A lock owned by another instance, or an older lock without an instance ID, is treated as active; visibility of a local PID cannot prove a process in another namespace has stopped. Stop all instances and verify that no operation remains active before removing a stale lock.

## Local preimage and commit protocol

After archive, manifest, checksum, path, entry, and quarantine validation, Root.ark constructs the preimage plan and stages these local domains before the first restore mutation. The staging root and backup-ID child are validated before coordinator creation, then checked again before deleting or writing staging files. Symlink/junction ancestors and an aliased backup-ID staging directory fail closed without creating a restore barrier.

1. `quarantine.json` and the configured quarantine payload tree, when quarantine state is present in the archive;
2. JSON state files present in the archive that restore will replace, plus the local backup-history state;
3. the complete `uploads/` tree when the archive contains an uploads tree;
4. the SQLite database and its configured sidecars when SQLite is enabled.

Preimage staging rejects symbolic links, hard-linked files, unsupported filesystem entries, changed files, and failed checksums. Staged files are copied through exclusive creation and hashed. A manifest records the exact paths, prior existence, file hashes, and directory entries; its SHA-256 digest is stored in the coordinator. On POSIX, staged files and directories are flushed before the coordinator advances to `prepared`. Windows does not expose a portable directory-entry flush through Node.js, so this does not claim power-loss durability on Windows.

Only after the complete preimage is verified does the coordinator move from `preparing` to `prepared`, and restore begin changing local state. The coordinator is durably updated around the quarantine, JSON, uploads, SQLite, and backup-history stages. Restore then writes a `restart_required` coordinator containing the selected and pre-restore backup records. That phase is the local commit boundary: provider reconciliation can proceed only after the restored state has restarted successfully.

If preimage creation stops while the coordinator is `preparing`, no restore destination has changed. Startup clears the partial preimage and coordinator only after it acquires the restore lock. If a failure or process interruption occurs while the coordinator is `prepared` or `rolling_back`, startup verifies the preimage and restores domains in reverse order, resuming safely after interruption. It performs SQLite and quarantine journal recovery before applying the whole-restore preimage. Replaying a domain restore is idempotent. After all local domains are restored, the coordinator durably advances to `rollback_complete` before deleting rollback material. A later startup in that phase retries cleanup without depending on the already-restored preimage manifest, so partial cleanup cannot turn a completed rollback into an unrecoverable manual-recovery state.

If a preimage is missing, corrupt, unsafe, or cannot be applied, Root.ark records `manual_recovery` when possible and refuses to start. It does not remove the barrier or guess that the pre-restore ZIP is sufficient. An in-process restore error also leaves the barrier active; restart the service to run automatic rollback. Tests inject failures at each local stage and use disposable data only.

While the restore and rollback protocols gate application traffic and background workers, they cannot provide one atomic filesystem transaction across different filesystems or protect against external writers that bypass the application gate. Other instances must use the shared gate and locks. Rollback itself is a compensating operation: clients or external processes outside the application may observe intermediate filesystem changes.

## Restart and external-provider reconciliation

After local commit, the coordinator changes to `restart_required`. The response recommends restarting every configured instance. Each instance loads the restored state, runs required migrations, and acknowledges only after its listener binds. Before the final acknowledgement clears the coordinator, the service retries removal of the transaction's extracted staging directory. A cleanup error keeps the barrier active and a later restart retries it. HTTP returns 503, and realtime clients are closed until the configured number of distinct instance IDs has acknowledged and local staging cleanup succeeds. Provider reconciliation workers stay behind the same barrier.

Cloud-provider actions cannot participate in one portable transaction with local files and databases. Once the local commit barrier clears, a provider outage may leave durable work pending or failed while local restored state remains authoritative. Retries use operation IDs and leases. Google Drive restore entries persist a stable generated or existing file ID before upload; retries target that ID after verifying the Root.ark key and configured parent. S3 retries use the same deterministic object key. This is resumable reconciliation, not distributed atomicity. Live provider credentials were not used for validation.

An archive can include files under `temp/` only when `BACKUP_INCLUDE_TEMP=true` or `BACKUP_INCLUDE_PENDING=true`; `temp/.chunks/` and `temp/.incoming/` remain excluded. Restore does not materialize these ephemeral files or add them to provider-reconciliation entries. Only archived `uploads/` entries are reconciled. The ZIP manifest records archived bytes; it does not promise that ephemeral temp state is restored.

## Durability and recovery limits

SQLite recovery-journal updates also use a fresh, exclusive same-directory temporary file, flush it, and atomically rename it over the primary journal. If writing an update is interrupted, the previous committed journal remains authoritative; a crash-left temporary is not replayed as the primary journal and may remain as an unreferenced file. On POSIX, directory `fsync` failures propagate and keep recovery fail-closed. Node.js does not provide portable directory-entry sync on Windows, so the same durability guarantee is unavailable there.

Coordinator and acknowledgement records use same-directory temporary files, file `fsync`, and atomic rename. Preimage files are flushed before the `prepared` phase. Restore destination file writes, directory replacements, quarantine updates, backup-state writes, and provider operations do not form one durably flushed transaction across all filesystems. The protocol is designed to recover process interruption; it does not promise recovery from sudden power loss or storage-controller failure, including on POSIX. Node.js also does not provide a portable directory-entry flush on Windows. The rollback protocol is not a cross-filesystem transaction.

Large preimages require free space for a copy of the local state being replaced. Insufficient space or a staging error fails before restore mutation. Full rollback can still fail because of later storage errors, permissions, interference by an external writer, or an unavailable filesystem; those failures keep startup blocked for manual recovery. Cloud-provider state is outside rollback and may require retries after the local commit. These boundaries are tested with temporary runtime directories; no real user data is used.
