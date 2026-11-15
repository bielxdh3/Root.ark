# Issue #63 — bounded local filter of an already verified catalog (partial slice)

## Architecture and acceptance, before implementation

The existing protected-index AES-GCM primitive is not fed by the production UI. This slice adds a literal substring filter to the existing **manual** `catalog-delta-list` operation, which already revalidates the owner-signed device grant, independently pinned owner head, CAS/witness signatures, and the complete catalog before locally decrypting AES-GCM metadata. The user imports the metadata key as a nonextractable, decrypt-only `CryptoKey` for each operation. No search is exposed outside this authenticated browser dialog.

**Searchable corpus:** only the filename of each current catalog version already returned by `readPrivateListing`. No file bodies, previews, historical backups, unrelated account/compartment, or legacy/server-search data. Logical-trash markers are visible in the unfiltered existing listing but never match a nonempty name query. Matching is literal case-insensitive substring with NFC normalization; no tokenizer, ranking, or special operators.

**Index and privacy:** no new index artifact or storage. The existing signed opaque catalog and AES-GCM metadata envelopes retain their format, identity/AAD, version/epoch checks and independent trust anchors. A manual search causes the same authenticated full-catalog reread as the existing listing and decrypts every row before applying the query locally. The query and plaintext stay in browser memory/DOM; neither is sent to a server, URL, audit log, browser cache, or persistent store. The server can still observe the ordinary catalog-read request and timing/count, not its search term or decrypted matches. A device without a current grant, independent pins, metadata key, or valid ciphertext receives no results.

**Lifecycle:** each action rebuilds results from the revalidated signed catalog and only the current locally imported key. Any changed CAS head, rollback, stale baseline, wrong key, malformed row, revocation, session logout, or account/compartment mixup fails the **whole** operation. No offline synchronization, migration/backfill, persistence, or cross-device index transfer is introduced. Existing close/logout handlers clear the displayed rows. The catalog's existing bounded signed-page validation continues to govern corpus size; this slice caps *displayed* search hits at 100 while reporting the total number of matches. Empty query preserves the existing full listing.

**Acceptance and regression:** (1) matching names visible in the authenticated dialog, unrelated names and trash excluded from nonempty results; (2) Unicode normalization and literal special-character filtering; (3) query longer than 120 UTF-16 units denied; (4) full decryption even when a match is absent, so corruption/wrong keys cannot yield a partial list; (5) no plaintext query in outbound requests or serialized opaque snapshots; (6) old unfiltered behavior, signed readback, revocation and logout checks unchanged. Validate with the existing signed-catalog/real AES-GCM browser fixture, focused Node tests and Edge UI probe.

This is partial functionality. Issue #63 remains open: secure population/lifecycle of a general protected search index, cross-device/offline semantics, richer search and wider acceptance are unresolved.

## Follow-up: persistent encrypted on-device filename index (stacked draft)

After the existing manual `catalog-delta-anchor` authenticates a device grant,
externally pinned owner head, CAS/witness head and signed opaque catalog,
`catalog-delta-list` can populate an encrypted local filename index. The first
search still decrypts **every** current AES-GCM metadata row in the browser,
including logical-trash rows and results past the 100-hit display limit.
The stored record contains only an AES-256-GCM ciphertext, random 96-bit IV,
format tag and nonsecret scope/owner/CAS pins. Its encryption key derives
locally using HKDF-SHA-256 from the freshly imported 32-byte metadata key,
with domain separation and account/compartment/keyring scoping. IndexedDB
storage never receives a plaintext name or query. No raw key is persisted.

On later searches (including after a page reload and a *new* authorized device
anchor), `verifyPrivateListingHead` **re-fetches** and verifies the complete
signed current catalog against external CAS/witness/owner pins and checks
every opaque row before cached plaintext can be decrypted. A changed head or
scope reindexes after a fresh full signed listing; a wrong key, tampered cache,
revoked grant, account mismatch, rollback, unavailable trust or invalid row
fails closed. The owner epoch/digest and exact catalog head are AEAD associated
data. Successful browser publish, trash or restore clears that scope's local
index; independently signed head checks protect against stale records even
if local cache deletion fails. Search and results remain in DOM/memory after
decryption; no filename or search term reaches an HTTP request.

This is **not offline search**: the fresh independent signed check remains
mandatory on every search. Site-data clearing removes the local cache;
users reimport their offline 32-byte metadata key. Corpus remains filenames
of current catalog versions only: no content full-text, cross-device transfer
of index artifacts, search ranking or historical backup search. Issue #63
continues beyond this bounded filename index.

## Follow-up: explicit, locally pinned text preview of one signed version

After manual owner/witness/CAS anchoring and filename selection, the owner may
choose **one** catalog revision and import three artifacts held separately
from the Root.ark server: the exact canonical content metadata JSON, its
32-byte per-version CEK, and a separately pinned SHA-256 digest of that CEK.
The browser rechecks the current device grant and independent owner floor,
performs the existing authenticated signed ciphertext GET, and verifies the
exact catalog object ID, revision, epoch and ciphertext SHA-256. Only then
does the existing file-content AES-GCM primitive authenticate the supplied
metadata and decrypt the envelope locally. The preview renders UTF-8 text
with DOM textContent, limited to 64 KiB and four passive MIME types; nontext
and oversized content are rejected. The browser clears the preview on input,
selection change, dialog close, logout and pagehide and zeroes temporary
Uint8Array secret/plaintext buffers after each operation.

**Trust limitation:** the separately supplied CEK hash is a comparison pin,
not an owner signature or a verified CEK distribution protocol. The owner
must independently authenticate its provenance and the offline metadata/CEK.
An arbitrary digest typed from the same untrusted CEK source proves nothing.
Without all imported material and a live signed GET, the preview remains
locked. The application server never receives the CEK, metadata document,
search term or plaintext. No persistent plaintext cache, automatic grant
redemption, encrypted key transfer, cross-device CEK provisioning or
production recovery guarantee is introduced; the separate #68 key-transfer
work is not changed.
