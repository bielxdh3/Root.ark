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
