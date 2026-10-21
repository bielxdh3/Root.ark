# Root.ark #65 — non-destructive browser legacy→protected copy

**EXPERIMENTAL CLIENT-ONLY COPY; NOT A PRODUCTION MIGRATION OR CUTOVER. NO-GO.**

This milestone reuses existing browser modules and does not change the normal
Root.ark migration/restore/provider routes or delete any user data:

1. `rootark-dev-vault-migration.js` retrieves only a deliberately selected
   legacy plaintext file via the current authenticated, same-origin
   `GET /files/:name` contract, bounded to 2 MiB. It rejects login HTML,
   encrypted legacy modes, unsafe filenames, redirects, incomplete lengths,
   oversized bodies and unsafe folder IDs. The legacy server already has
   plaintext visibility for this pre-ZK source; that is **not** retroactive ZK.
2. `rootark-zk1-legacy-protected-copy.js` freezes the selected source identity,
   authenticated scope, manifest revision/digest, epoch and current device
   signing context before network I/O. It rejects a mismatch between
   current-epoch destination metadata and signed scope, and requires a new
   `parent_version_id:null` destination. Filename, MIME type and bytes are
   sealed exclusively in browser WebCrypto AES-256-GCM with a user-held
   nonextractable CEK. Only ciphertext, opaque metadata and Ed25519 signed
   operation cross the protected HTTP boundary.
3. The client computes an independent one-frame ciphertext root *before*
   upload, signs the original ciphertext digest with the active device key,
   submits an authenticated PUT and performs a **fresh nonce-bound signed
   historical GET** of exactly revision 1. It checks the signed ciphertext
   digest, independently computed root, AEAD-bound metadata and recovered
   client-only plaintext against the original legacy source.
4. It rereads the legacy source after the protected read-back to detect changes
   during the copy. It never calls deletion, source reclassification, rename,
   reference switch or server-side decrypt. It scrubs its own browser plaintext
   and ciphertext buffers on completion/failure. Success returns only
   `protectedCiphertextLocallyVerified:true`, `sourceRechecked:true` and
   explicit `authorizesCutover:false` / `canDeleteLegacy:false`; no plaintext.

## Evidence

`node --test test/issue-65-browser-legacy-protected-copy-http.test.js`
uses actual loopback Express HTTP, authentication middleware and the existing
protected SQLite append-only store, fixture-only signed witness adapter,
nonextractable WebCrypto Ed25519 + AES-GCM keys and deliberate login headers.
The test checks plaintext never appears in protected SQLite, the original
legacy HTTP source remains byte-identical, and the ciphertext can be
independently re-read and decrypted by the client. A browser VM loads six
plain UMD modules in dependency order with **no Node require** and performs the
same end-to-end copy. Adversarial cases include legacy source changing before
the second read, PUT committing with its HTTP acknowledgement lost, and a
same-origin GET response with substituted ciphertext. Each returns a denial
without deleting the original or making a second PUT; any already-stored
opaque target is retained as evidence for later explicit reconciliation.

## Explicit incompleteness

The fixture legacy route is *contract-compatible* with the known legacy file
GET interface, not a verified full production UI/server integration. Its
witness is synthetic within one machine; neither provider identity nor a
monotonic independently managed object root catalogue is proven.

The two legacy reads can race a third modification. An ACK-less PUT can be
durably committed even though the client returns a denial; this flow cannot
decide terminal status without independent CAS/witness proof. Nothing here
authorizes removal or replacement of real plaintext, reference/collaboration
rewrite, trash/version/backup/sync/WebDAV migration, permission revalidation
through all providers, S3/Google Drive physical STOP, or production ZK. No
changes were made to production data, credentials or provider configuration.
No unknown Docker volume was deleted. All production migration and release
gates remain **NO-GO**.
