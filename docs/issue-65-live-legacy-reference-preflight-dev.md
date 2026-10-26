# Issue #65 — LIVE legacy reference metadata preflight (DEV, opt-in)

**NOT a complete migration/backup inventory. No cutover, legacy deletion, or owner-signed completeness.**

`src/services/zk1LiveLegacyReferencePreflight.js` adds an explicit, synchronous
`inspectZk1LiveLegacyReferencePreflight({optIn, databasePath, persistence})`.
It opens an **existing** SQLite database with `node:sqlite` using
`{readOnly:true}`, sets `PRAGMA query_only=ON`, and scans under one local
SQLite read transaction. It does not call the application's `getDb()`, create
database files, execute schema migrations, repair objects, or register an HTTP
route. An operator must independently authenticate and authorize the caller;
do **not** bind this raw function to a public or ZK data-plane endpoint.

Activation requires `optIn:true`, an absolute existing SQLite file, and an
explicit `persistence` assertion:
`{dbEnabled:true,jsonReadFallback:false,jsonWriteMirror:false}`. Obtain
those settings and the database path from the application's own `db`
configuration; refuse JSON fallback/mirror modes rather than treating empty
SQLite tables as evidence that legacy records do not exist. An unavailable
table, malformed metadata JSON, unexpected scalar type, oversized row, scan
above 5,000 entries per class or renamed/replaced database file causes a
generic `ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE` refusal.

## Observed LIVE sources

| Reference class | SQLite source | Precisely what is observed, not proven |
|---|---|---|
| versions | `file_versions` | Version-history container rows; JSON history is parsed but stored bytes are not independently verified |
| backups | `backup_history` | All backup history rows, **not** ZIP manifests, cloud replicas or backup contents |
| trash | `trash_items` | All lifecycle states, not just active trash; trash filesystem and remote copies unverified |
| links | `public_links` | Includes revoked links, unlike the active-only repository loader; permissions and external share replicas not proved |
| derived | `file_search_index` | Non-protected FTS index **only**; thumbnails, previews, analytics and other derived artifacts remain unknown |
| retention | `file_expirations` | File expiration metadata **only**; backup retention policies, filesystem tombstones and retention transactions remain unknown |

The legacy HTTP server has additional JSON fallbacks/mirrors, archive
directories, trash paths, remote S3/Google Drive objects, WebDAV/sync,
quarantine and other derived data. They are **not** covered by these six SQL
queries. The ZK protected store uses separate opaque object/catalog/epoch
authorities and is deliberately **not** traversed by this adapter. SQLite
metadata can be visible to the legacy server even where file bodies have
different encryption modes; the resulting observation does not mean those
bytes were decrypted or copied.

The response contains only six fixed class names, bounded counts, per-run
random-key HMAC fingerprints, and explicit confidence flags/blockers. It never
returns source filenames, paths, provider IDs, share tokens, record JSON,
signing material or the HMAC key. These ephemeral fingerprints cannot be
linked between invocations and **must not** be treated as independent
signatures or authoritative rollback floors. It always declares:
`legacy.coverage="partial"`, `protected.coverage="uninspected"`,
`snapshotOwnerSigned=false`, `authoritativeCorpusInventory=false`,
`wholeCorpusVerified=false`, `canDeleteLegacy=false`,
`authorizesCutover=false`.

## Evidence and blockers

`test/issue-65-live-legacy-reference-preflight-http.test.js` exercises actual
SQLite source tables with private synthetic sentinels and a locally bound HTTP
fixture whose test-only authentication gate forwards **only** the sanitized
report. It rejects unauthorized requests, missing tables, malformed JSON,
unknown overflow above the scan limit, unavailable databases and enabled JSON
fallback/mirroring. Both Node 22 and Node 24 run these focused tests. The
HTTP fixture is **not** registered in the application; production authorization,
rate limiting, mTLS, origin policy and cross-provider reconciliation are
unimplemented for this experiment.

Adversarial RED: a test-only in-memory loader forced
`authorizesCutover:true` on the partial report; **2 PASS / 2 FAIL** (the
direct validator and HTTP contract both rejected the invented permission).
The loader was removed without changing tracked code. GREEN with the real
implementation: **4 PASS / 0 FAIL** on each of Node 22 and 24. This RED is a
deliberate unsafe mutant, not a regression observed in the previous product.

Before any *complete* snapshot or owner signature can be considered, a trusted
enumerator must include **all** actual legacy filesystem, historical versions,
trash, backup archives, pending retention transactions, links and external
providers, with stable generation/fence, collision-free joins, content
readback, owner-scoped authorization and independent monotonic persistence.
An incomplete or unknown class is never converted to an empty/clear class.
The returned report is diagnostic only.

## Independent local backup/history/alias/retention evidence (opt-in extension)

The optional `backupDataDir` argument (an existing absolute legacy `data/`
directory containing the selected SQLite file) invokes
`zk1LiveLegacyBackupEvidence.js`. It is NOT enabled automatically. The
extension reads a second, independently observed local source:
`data/backup-history.json` if present and the ENTIRE
`data/backups/` namespace. It checks registered archive basenames against
the SQL `backup_history` IDs/statuses/checksums. JSON backup-history mirrors
must match SQL identities when present, even if database fallback is disabled;
stale/malformed/orphan mirrors refuse, rather than becoming evidence that old
archives do not exist. A missing mirror is reported as `jsonHistoryRows:null`
and is **not** interpreted as an empty historical corpus.

The physical scanner recognizes `rootark-(backup|pre-restore)-...`.zip
archives, paired `.retention-tombstone` and `.retention-tombstone.json`
files, and `.retention-transactions/tx-<uuid>/transaction.json` states
(`prepared`, `archive_moved`, `history_removed`, `cleanup_committed`).
Each named artifact must correspond to an unambiguous backup ID/filename.
Where present, backup checksums are checked against independently read bytes;
transaction and tombstone checksums and their canonical local paths must
agree with the corresponding physical aliases and histories. No
`recoverRetentionTombstones`, `cleanupRetention`, rename, unlink, SQL
mutation, cloud GET or protected ZK route is called. Links, junctions, hardlink
aliases, extra/unrecognized backup filenames, staged/incomplete forms,
malformed transaction JSON, duplicate backup IDs, missing successful backup
archives and unsupported unknown references cause an explicit refusal.

The bounded experiment scans at most 5,000 entries per directory, 32 MiB per
file, **64 MiB aggregate**, 256 KiB per metadata JSON, and rechecks every
inspected file identity/size/mtime/ctime and directory identity at the end.
Backups exceeding these limits intentionally fail closed; no production
backup workflow uses this inspector. Ordinary concurrent legacy writes,
undetected same-size same-time substitutions, Windows power-loss durability,
privileged filesystem attacks, cloud staging and remote-only snapshots remain
unproved; a real authoritative inventory requires independent generations,
quiescence, archive ZIP manifest verification, remote copies and signed owner
authority. The physical content may still be server-readable legacy data;
**never** forward it to the ZK plane.

The response adds only `legacy.backupEvidence` with bounded numerical counts,
`globallyComplete:false` and a per-invocation HMAC. It contains no raw
filenames, paths, archive bytes, account IDs or private keys. With no
`backupDataDir`, the field explicitly says `observation:"uninspected"`.
All prior `wholeCorpusVerified:false`, `authorizesCutover:false`,
`canDeleteLegacy:false` and `snapshotOwnerSigned:false` guarantees remain.

`test/issue-65-live-legacy-backup-evidence.test.js` uses disposable real
SQLite, filesystem/retention fixtures and a localhost authenticated HTTP
**test-only** wrapper. It tests forged history, extra hardlink/alias/archive,
corrupt/missing payload, mismatched checksum, tombstone and transaction drift,
unsafe paths, unknown reference classes, oversize refusal and source survival.
The existing six-class SQL and unrelated legacy tests remain separate.
An in-memory mutation that bypasses this second independent inspection was
RED **0 PASS / 7 FAIL**; this is an intentional insecure mutant, not a prior
production regression.

### Optional ZIP reference metadata inspection (DEV)

Set `zipContentsOptIn:true` **together with** `backupDataDir` on the
read-only live reference preflight. This inspects the central directories of
each selected, independently checksummed local ZIP archive and retention
tombstone. The bounded scanner validates EOCD, local/central header identity,
single-disk layout, duplicate/case aliases, path traversal, encryption flags,
ZIP64 sentinels, entry metadata and declared-size limits. An unrecognized ZIP
container or unsafe name refuses the entire scan rather than becoming an
empty archive.

The optional `legacy.backupEvidence.archiveContents` report contains only
counts for manifests, SQLite candidates, derived candidates, directories and
**unknown** entry classes, plus an ephemeral keyed fingerprint. All source
filenames, archive paths and entry names remain private. It does **not**
decompress or cryptographically read back individual entry content, establish
the correctness of backup-manifest.json, cover external provider namespaces,
prove archive or derived completeness, or authorize restore, cutover/deletion
or production use. `contentReadbackVerified:false`,
`derivedCoverage:"unknown"`, `providerCoverage:"unknown"` and
`archiveCompleteness:"unknown"` are explicit. Omitting the option preserves
the previous partial backup observation unchanged.

## Local version payload and derived search reference evidence (third independent opt-in)

The optional `localUploadsDir` is the existing absolute canonical legacy
`uploads/` directory, supplied by an authorized local operator. With this
argument the inspector additionally performs bounded, synchronous, read-only
inspection through `zk1LiveLegacyLocalReferenceEvidence.js` in the **same**
SQLite read transaction as the six source classes and optional SQL/backup
gates. No default activation, HTTP registration, read repair, local file
mutation, or protected object access occurs. It must only be used when the
operator expects local bodies to be available; cloud-only or incomplete caches
refuse on missing referenced files.

The scanner maps `file_versions.versions_json[*].storedAs` to the actual
`uploads/` root (folder ID `root`) or one-level `uploads/<folderId>/`
directory according to `folders.id`, checks declared sizes and current
version identity, and requires each `file_search_index` `(folder_id,file_name)`
derived reference to resolve to a local regular file. It reads and hashes
actual file bytes without exporting them. It enumerates **all** entries in
the chosen `uploads/` namespace; unregistered regular files are counted as
`unmappedLocalFiles`, never assumed to be safe to delete. Unknown directories,
symlinks, junctions, hardlinks, unsafe names, duplicate aliases or derived
references, invalid/stale version metadata, unavailable historical payloads
and changes in file/directory identity during the scan cause a generic refusal.
At most 5,000 combined files/directories and 5,000 rows per class are examined;
per-file content is limited to 32 MiB, aggregate bytes to 64 MiB, JSON to
256 KiB. Larger real corpora intentionally refuse rather than truncate.

`legacy.localReferenceEvidence` emits only counts, a fresh-key HMAC per run,
`globallyComplete:false`, and the label
`partial-local-legacy-file-references-only`. Without the option it explicitly
returns `observation:"uninspected"`. All top-level destructive/cutover flags
remain false. This establishes **local existence and observational identity
only**, without signed owner permission, archived ZIP manifest coverage,
remote provider inventories, trusted baseline, durable monotonic rollback
floor, full derived previews, untracked paths elsewhere or cross-source
quiescence. A coordinated rollback of *both* database and files cannot be
detected from this local snapshot; adversarial tests reject an inconsistent
SQL rollback that references missing bytes. Readback also cannot prevent an
unprivileged writer from mutating a file between the final identity check and
another process consuming it.

`test/issue-65-live-legacy-local-reference-evidence.test.js` verifies real
SQLite, local version bytes, physical derived targets, unknown/unmapped files,
symlinks/junctions/hardlinks, missing historical versions, stale SQL rollback,
late same-path replacement, and a combined migrated SQLite + backup archive
+ local upload fixture. The test includes a RED/GREEN contract for the
otherwise absent opt-in report.
