# Issue #65 — owner-verified legacy transition (DEV)

The legacy workflow now has an optional, client-verifiable signed transition
for ONE individually pinned legacy version to ONE protected ciphertext
object/revision. Legacy deletion and full account cutover remain blocked.

1. The existing beginLegacyMigration copies client-side plaintext into a
   ciphertext-only protected PUT, persists a strict IndexedDB intent before
   PUT, and reconciles uncertain ACK exclusively with signed GET. The
   existing finalizeLegacyMigration verifies an independently owner-signed
   ciphertext-root checkpoint, without authorizing cutover.
2. prepareLegacyMigrationTransition requires the exact historical sourcePin,
   current owner-signed head and device grant, CEK, journal, and signed
   owner-root checkpoint. It rechecks authenticated protected GET/readback,
   legacy source SHA/MIME/Last-Modified and owner proof. It returns an unsigned
   proposal with a new nonce, containing no plaintext or CEK.
3. In the offline owner process, use
   RootarkZk1LegacyTransitionReceipt.signTransitionReceipt with proposal and
   nonextractable ownerSigningKey. The owner should independently compare
   scope/head/legacy provenance and the protected root before signing.
4. stageLegacyMigrationTransition imports that signature and repeats
   every owner/grant/source/protected signed GET check. It verifies the exact
   signed proposal and strictly CAS-persists the receipt beside the existing
   migration intent. A replay of the same receipt is idempotent; a competing
   signed receipt or stale/foreign input is rejected. Retrying stage never
   resends an uncertain PUT.

runLegacyMigrationBatch also accepts optional transitionApprovals, one
per selected entry, either null or a signedRootCheckpoint and
signedTransitionReceipt pair. Results report partial, mixed or
verified-protected; these labels cover ONLY selected versions, and cannot
prove the entire legacy corpus is protected. Each historical version retains
its deterministic target object/version references and own signed receipt.

Receipts bind: source scope and legacy locator, version and storedAs,
uploadedAt, SHA-256, size, MIME, Last-Modified, protected target object and
version ID, ciphertext root/SHA-256/epoch/revision, current owner head,
crash-safe binding, source descriptor digest, nonce and issuedAt. Five
derived-reference statuses (links, backups, trash, retention, derived) remain
explicitly unknown. Attempts to assert they are cleared fail closed.

Permanent limits: canDeleteLegacy=false, authorizesCutover=false,
wholeCorpusVerified=false. The current legacy API has no complete reliable
link, backup, trash, derived reference and retention graph; off-provider
durability is not proven; IndexedDB can be lost or rolled back. The owner
should independently retain signed receipts and head checkpoint. The old
legacy server continues to expose legacy plaintext to the authorized
client, and the protected service receives only ciphertext.

Validation: issue-65-browser-legacy-resumable-migration-http.test.js uses
disposable authenticated Express/SQLite protected HTTP routes and exercises
interrupted CAS, lost ACK, changed source and mixed batch. The separate
issue-65-legacy-transition-receipt.test.js validates offline signatures,
tampering and browser UMD portability.
