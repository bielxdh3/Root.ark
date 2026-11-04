# Issue #65 / W147 — experimental strict-mode backup and job denial

## Status and scope

This patch adds **deny-only, opt-in protection** around selected whole-instance
legacy backup and background cloud I/O paths when
`ROOTARK_ZK10_SYNC_CUTOVER_STRICT` is set to a nonempty value other than `0`
or `off`. It is NOT a production ZK10 cutover, a positive grant, an
independent off-host floor, or a monotonic account enforcement mechanism.
It does not make plaintext already held by the server zero-knowledge.

The existing legacy behavior is unchanged with STRICT unset / `0` / `off`.
With STRICT requested and **without a genuinely configured external
multi-account owner/corpus authority**, the server must not attempt any
whole-instance ZIP backup or legacy replay of the covered cloud jobs:

- The backup service refuses archive creation (manual, automatic,
  pre-restore), collection and direct ZIP streaming before reading/staging
  source files. It also rejects direct backup-archive lookup.
- The authenticated `/backups` route module denies list, status, ZIP
  download/manifest, create, restore, and delete with a bounded
  `503` + `Cache-Control: no-store`. This supplements, but does not rely
  exclusively on, the existing strict HTTP GET/HEAD guard in `server.js`.
- The scheduled automatic backup is not registered in STRICT; the backup
  service guard remains authoritative for manually invoked cron callbacks.
- Whole-instance restore and backup cloud-restore synchronization deny before
  proceeding. The durable cloud mutation queue refuses background provider
  uploads/deletes in strict mode, including persisted work after a restart;
  its pending records stay retryable. Startup/periodic cloud temp, upload,
  trash and restore reconciliations are paused at `server.js`.
- Independent review W150 found a separate startup-only
  `reconcileUnknownProviderInventory()` → `processRestoreSyncInternal()`
  bypass of the public `processRestoreSync()` wrapper. Both internal entry
  and the provider upload point now re-check STRICT. A healthy/known inventory
  returns without cloud I/O; an unknown marker or pending restore queue remains
  denied under STRICT rather than silently acknowledged.
- Independent review W155 found that `processPendingCloudTrashItems()` was
  not the only path to physical remote DELETE. Automatic trash expiry,
  authenticated single/bulk trash routes, and direct
  `trashService.processRemoteDeletion()` called the provider without the
  ZK10 guard. Strict now denies *before* automatic expiry queues a destructive
  operation, before either HTTP DELETE route, inside the shared trash
  dispatcher (including after asynchronous replacement checks), and at
  physical `deleteFileFromCloud`/`deleteCloudPrefix` plus
  `deleteCloudTrashItem` boundaries. These are deny-only fences, not a
  permission to delete during real independent-owner cutover.

The queue test invokes the **real queue and durable disk records** with a
disposable provider sink. It does not claim an actual S3/Google Drive
acknowledgement.

## Reproduced behavior

1. **Before patch (RED):** a fresh child process with `STRICT=1` invoked
   the real backup service and created a ZIP containing test-only plaintext.
   Even after the service denial was added, an actual JWT-backed
   `POST /backups` returned an unrelated `500` instead of a definitive
   strict `503`. The real cloud queue replayed the persisted upload job under
   `STRICT=1`. Each failing test was observed before its implementation.
2. **After patch (GREEN):** source ZIP/restore/scheduler, authenticated
   backup HTTP routes, and durable queue retry deny in STRICT. Under OFF
   the same fixtures can create/read/download the ZIP and process the queued
   job. Tests use only throwaway directories and markers.
3. **Remaining critical RED (not claimed as GREEN):** restart with
   `STRICT=0` after `STRICT=1` reopens the previously created ZIP.
   This downgrade is fundamentally possible while the only enforcement input
   is mutable local configuration. No local database/flag can attest a
   formerly enrolled account or supply an independent floor.

4. **W150 P1 RED→GREEN:** a real reference ZIP with
   `cloud_complete: true` and an unknown durable inventory marker was created
   under OFF, followed by a real post-backup plaintext delta. In a new
   process, the cloud provider's enabled callback advanced STRICT to `1`
   after historic ZIP validation but before the internal startup upload.
   Before the P1 fix, `reconcileUnknownProviderInventory()` uploaded those
   plaintext bytes anyway and durably marked the inventory `reconciled`
   despite STRICT=1. The new source/physical-I/O checks prevent the upload,
   propagate the specific 503-class denial, and preserve the unknown marker.
   A separate test advances STRICT inside a Drive stable-file-ID reservation
   after the internal lease is claimed; it likewise rejects before PUT.
   A later fresh OFF process still retries exactly once and marks reconciled.
   A separate healthy-inventory fixture proves strict startup does not
   accidentally stop serving all authenticated routes.

5. **W155 P1 RED→GREEN:** actual persisted `queueRemoteDeletion()` was
   reloaded in a fresh process with STRICT=1 and invoked via the genuine
   `trashService.processRemoteDeletion()` dispatcher. Before the patch,
   the disposable provider callback physically deleted the object and
   `state=completed`; the test failed with `deletes=1`. After the patch,
   file *and* folder-prefix records retain `remote_delete_pending` and
   `state=pending` and no DELETE occurs. A second late-switch test changes
   STRICT while awaiting replacement validation; it also denies before
   claiming the operation. A restarted OFF worker then deletes exactly once.
   A separate full `server.js` HTTP integration test boots with genuine
   expiring trash, `TRASH_AUTO_CLEANUP_ENABLED=true`, real JWT login and
   a disposable HTTP S3-compatible endpoint: STRICT=1 produces no S3
   DELETE, both authenticated trash DELETE routes return 503/no-store, and
   no trash record/local bytes are destroyed. Restarting under OFF delivers
   a real HTTP DELETE to the S3 fixture and marks the item completed.

   This independently closes the *observed local-STRICT* paths, but it
   cannot cancel a DELETE already accepted by the provider, prevent direct
   infrastructure/operator access, or make local STRICT monotonic across
   external restarts or flag rollback.

## Blocker to safe positive authorization and completed #65

Whole-instance ZIPs include shared JSON and SQLite snapshots, all uploads,
optional temp/pending files and cloud inventory, potentially crossing many
users and derived objects. A logged-in `manageBackups` administrator is
**not** a cryptographic owner of all archived contents. A signed permit for
one username/object/lease cannot authorize a multi-account ZIP, and direct
filesystem operators can still access historical plaintext ZIPs.

Before allowing even one byte under a true `protected_enforced` cutover:

1. Deploy and independently verify physical custody of a signer, monotonic
   external CAS/witness and its retained minimum, including after database
   restoration, instance restart, key rotation and witness rollback.
2. Obtain an authenticated immutable mapping and complete **account-wide**
   corpus/inventory, including ownership of snapshots, versions, trash,
   derived artifacts, cloud objects and existing ZIPs, plus verifiable
   never-enrolled negative membership.
3. Design atomic multi-owner admission, expiry/cancellation and streaming
   authorization for the whole archive, or replace global ZIP with
   independently authorized per-owner exports. Suspend/abort active jobs
   before transitions and re-check authority at physical provider/ZIP IO.
4. Test real external authority and custody under restart/revocation/rollback,
   cross-account readback, POSIX other UID and Windows; no mock or
   co-hosted signed fixture can substitute for off-host provenance.

**This patch does not protect against a local operator resetting STRICT to
`0`, other unguarded synchronous legacy APIs, pre-existing uncontrolled ZIP
copies, or direct filesystem/cloud-provider access.** It must not be called
full ZK10 or considered merge-ready issue #65 by itself.
