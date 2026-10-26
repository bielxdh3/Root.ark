# Root.ark #65 — S3 and Google Drive migration readiness preflight

**Date:** 2026-10-21
**Status:** experimental READ-ONLY; not a reversible migration or release authorization.

`src/services/zk1ProviderMigrationPreflight.js` consumes the application's
existing `createCloudStorage()` read-only `status`, `enabled`,
`resolveInventoryContext`, and `inventory` APIs, with no calls to `download`,
`upload`, `remove` or `removePrefix`. It supports only S3 and Google Drive
inventory (the only remote providers backed by this exact existing API).
The compatibility checks reject a disabled or changed provider identity,
duplicates, malformed object keys, unsupported inventory areas and lists over
10,000 entries. Before and after listing, it resolves the authenticated
provider/namespace identity and refuses mismatches; **this is not** an
atomic provider snapshot, and remote object contents are not read or hashed.

Reports disclose only the provider class, `uploads`/`temp` area,
non-correlatable per-run HMAC-SHA256 opaque object references, object count
and explicit blockers. Private names, paths, bucket IDs, Drive file IDs,
principal IDs, credentials, keys, passwords, and raw cloud key names are not
reported or logged. This differs from a usable migration mapping: the HMAC
secret is deliberately discarded after each report. No source metadata or
real provider files are modified.

Four targeted Node tests pass, including existing `createCloudStorage()` S3
`ListObjectsV2` and Google Drive `files.list` adapters exercised through
disposable *in-process fake remote clients*, malformed/duplicate inventories,
identity drift and private-field leak checks. This is integration with the
real **adapter code**, not a claim that real AWS/Google accounts were
accessed, listed or modified.

The report always sets `readOnly=true`, `canMigrate=false`, and
`rollbackReady=false`. Coverage remains incomplete for local disk, WebDAV
(an access path over the underlying provider, not an independent cloud
provider here), historical versions, backups, trash and sync. No ciphertext
integrity checks, trusted owner/keyring proofs, dual-read/write migration,
provider-independent fencing, post-copy verification or rollback are supplied.
Consequently, this preflight must **not** be interpreted as approval to copy,
delete, cut over, restore or migrate live Root.ark data.
