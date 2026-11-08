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

## Follow-up: bounded local text search across owner-selected versions

The DEV workspace now offers an explicit **Search inside selected versions**
action. It examines **1–128** exact object/revision pairs in a freshly signed
current catalog, with a nonempty NFC/case-insensitive literal text query
(maximum 120 UTF-16 units). Each version gets its own fresh signed GET,
current independent owner/head/CAS and device grant checks, matching
ciphertext digest, separately pinned owner-held CEK SHA-256 and local AEAD/UTF-8
opening using the existing single-version preview, **sequentially in windows
of eight at most** (only one active GET/CEK/plaintext per iteration). Supported
text is bounded to 64 KiB per file; matches show at most a 160-character local
excerpt. The sole cross-window collection is up to 128 verified excerpts,
not a persistent or aggregate full-text cache.
A single revoked, tampered, malformed or wrong-key version aborts the **whole**
batch without revealing even earlier matches. Progress reports the count
of revisions verified (0/128, 8/128, etc.), never matches/names/terms.
An optional **Todas as palavras (AND)** checkbox switches from the default
contiguous literal phrase to a conjunction of **2–4 distinct literal tokens**,
independent of order. The entire query remains at most 120 UTF-16 code units;
each token is 1–40 UTF-16 code units. NFC normalization and locale lowercase
apply before local matching; Unicode whitespace separates tokens (multiple
spaces collapse), while C0/C1 controls, DEL and Unicode line separators are
rejected. Repeated tokens after normalization/case-folding are rejected rather
than silently collapsed; punctuation is literal, not a regex or search operator.
Every token must appear somewhere in the **same** verified UTF-8 version;
the excerpt anchors to the earliest occurrence of any required token, and
matching does not trigger extra HTTP requests, keys, catalog reads or indexing.
Invalid input fails before any signed GET. The unchecked default preserves
the original single-phrase behavior, including embedded spaces.
An explicit cancel button remains enabled during verification; cancellation
stops subsequent windows and drops the result atomically, although an already
in-flight signed GET may complete before the final cancellation check.
No plaintext/query/CEK is sent
to Root.ark, and no persistent plaintext/content index, PUT, rollback, server
search, automatic key delivery, off-host custody or production release is
claimed.

The user imports a JSON manifest no larger than 64 KiB. It has exactly
`schema: "rootark-zk1-local-text-batch/v1"` and `entries` (1–128 records).
Each entry has exactly `objectId` (opaque 16-byte base64url), positive
`revision`, the canonical eight-field `metadata` document from the
original protected version, `cekFile` (local filename), and `cekSha256Pin`
(base64url SHA-256 of the 32-byte file key). Import exactly one separately
preserved 32-byte CEK file per record, all with distinct names. Independently
confirm the manifest's SHA-256 using the additional **manifest pin** input.
The opt-in checkbox is an operator assertion of independent verification,
not server-provided proof. Obtaining that pin from the same untrusted source
as the manifest would offer no provenance.

For a multi-window search, only one CEK is read into a Uint8Array **after**
that revision's authenticated ciphertext GET; it is zeroed in a per-file
`finally` before another CEK is read. The older 1–8 caller path remains
compatible, but larger selections must use disposable CEKs via `readCek`.
Ephemeral search results are cleared on input change, cancellation, logout,
dialog close and pagehide. Browser-managed JavaScript strings cannot
promise deterministic memory scrubbing. Real signed two-device HTTP GET,
local AES-GCM, 64-file lazy-window processing and CEK erasure,
signed disposable nine-version HTTP with forged final response (no partial
results), grant/scope/epoch negative cases, bounded input and real Edge CSP
`textContent`, explicit cancellation and logout tests cover the slice.
The independent authority source/pins and owner-held CEKs remain mandatory;
the test HTTP adapter is disposable, not a production authority.
General protected content
indexing, persistence, safe key provisioning and external acceptance remain
unresolved Issue #63 scope.

## Explicit rotation of an existing protected revision index

When the encrypted device-local index holds 128 selected revisions, the owner
can explicitly opt to **replace** the previous selection using a new,
independently pinned, fully verified 1–128-revision batch. Replacement requires
both the normal persistence checkbox and a separate unchecked replacement
checkbox. Older selected plaintext is not decrypted or retained. One
conditional IndexedDB transaction replaces the AES-GCM snapshot; invalid
inputs, an expired grant/session, concurrent scoped clear, or exceeding the
4 MiB JSON limit deny the replacement write. A concurrent clear retains its
durable tombstone; no rejected operation resurrects the previous plaintext.
Old search pages are invalidated by the new snapshot nonce. Ordinary append
still rejects overflow. This feature does not provide a complete historical
index or increase the 128-revision resident limit.
