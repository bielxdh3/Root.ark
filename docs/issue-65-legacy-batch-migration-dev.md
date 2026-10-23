# Issue #65 — legacy historical batch migration (DEV only)

The browser-only `rootark-zk1-legacy-batch-migration.js` exports
`runLegacyMigrationBatch({ optIn, entries, migrationSecret, trust, origin,
fetchImpl, journal, nowSeconds })`. It is a bounded opt-in **copy**, with at
most 12 selected source revisions per call. No automatic legacy deletion,
reference switch, trash restoration, provider durability claim, or production
authorization is possible. It is intentionally not connected to the shared
authenticated workspace UI.

Each entry contains `{ legacy: { name, folderId }, sourcePin, cek }`.
`sourcePin` must contain exactly `version` (positive number), `storedAs`,
`uploadedAt`, `size`, `lastModified` (canonical HTTP GMT timestamp),
`sha256` (base64url of 32 digest bytes), and `mediaType` (normalized MIME).
The user must explicitly review a source selected from authenticated
`GET /versions/:filename?folderId=...`, and pin bytes, MIME and Last-Modified
from authenticated `GET /download/:filename/v/:version?folderId=...` before
opting into migration. This reading happens only on the legacy side. The
existing server version history supplies identity metadata, but no stored
cryptographic digest; **the client must pin the actual file digest**.

Use a locally generated 32-byte `migrationSecret` and independently retained
per-entry non-extractable AES-GCM CEKs. Keep those, the reviewed source pins,
the externally signed owner checkpoint, and the latest monotonic head safely
outside the application server; supply **the same material** when resuming.
The migration secret serves HMAC-based deterministic ZK `object_id` and
`version_id` derivation for each account, owner pin, head and selected
historical version. Historical revisions become **separate protected objects
at revision 1**, rather than fabricating a ZK revision chain.

Before and after a copy, the browser compares authenticated version metadata
to the pinned history selection. It also validates the complete source's
SHA-256, MIME and Last-Modified before encrypting, and again after a signed
protected GET verifies the posted ciphertext. The existing journal records
intent through strict IndexedDB CAS before PUT. If PUT ACK or GET is lost,
retry performs **GET only**: an unknown PUT is never repeated. The journal
stores ciphertext and digests, not legacy plaintext. Each result requires a
separate independent signed owner ciphertext-root checkpoint before the
existing per-object finalize flow; local readback alone is not a durability
or retention proof.

**Known limits:** the legacy `GET /trash` lists metadata but there is no
authenticated non-destructive historical plaintext download for a trashed
item, so trash is unsupported and fails closed. A file with no accessible
version catalog or no Last-Modified also fails closed. A changed owner grant,
recovery head, source, missing local IndexedDB state, lost client key/secret,
absent signed GET, or concurrent conflicting target cannot be auto-repaired.
Source metadata, timing, scope and file size remain visible to the server.
This does not prove external custody, independent durability, atomic
multi-object migration, or readiness for production.
