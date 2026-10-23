# Browser ZK1 opaque catalog (Issue #65)

Optional development-only UI inside the authenticated ZK1 workspace. The
server advertises `opaqueCatalogV1: true` only when an independently pinned
Ed25519 catalog CAS authority has been injected. The standard development
bootstrap leaves it disabled. No generic sync-v2 API is ever used for ZK1.

An authorized **second device** must independently import: raw owner Ed25519
public key and its externally pinned SPKI digest, a currently signed device
grant, complete owner checkpoint history and independently confirmed manifest
head (existing ZK1 workspace fields); its own PKCS#8 private device key;
the **other** catalog-writing device's owner-signed current grant; the
independent catalog CAS Ed25519 raw key plus externally pinned SPKI hash; and
the exact current catalog sequence and digest obtained outside Root.ark.
Optionally it may import a 32-byte local catalog metadata AES key. Keys and
name/path plaintext stay in the browser.

After owner history, grant and IndexedDB owner floor verification, the browser
uses a fresh signed device challenge for **every** page and checks the exact
catalog signature, signer grant, Ed25519 CAS statement, scope, epoch, count,
page hash, nonce and 30-second authority freshness. It refuses a missing
externally pinned catalog head or unknown signer. On success it atomically
updates a separate IndexedDB high-water mark keyed to scope and CAS SPKI,
returns the fully verified opaque version list, and highlights page digests
that changed since the previous session. The UI displays at most 32 items per
page, decrypting names via AES-GCM only when the user reimports the metadata
key. A selected version's ciphertext GET is independently device-signed and
checked against the catalog's SHA-256 digest. No plaintext or CEK is sent or
restored to the server.

Page/list/GET run behind the existing authenticated session, permission and
CSRF middleware. The workspace's session epoch, dialog lifetime, and
double-submit CSRF cookie are checked after awaited crypto/network operations
and immediately before local download. Logout clears the result and revokes
temporary download URLs. Only ciphertext is offered for download.

**Deliberate limitations:** no authenticated mutation, delete, move, rename,
trash, automatic import of new head, production deployment, independent
genesis completeness proof, or multi-host linearizability proof. The catalog
currently has at most **4,096 versions and 128 signed revisions**. Once 128
heads are committed, further writes fail closed until a separately reviewed
owner-signed rollover/checkpoint protocol exists. If a catalog signer is
revoked, the existing server refuses reads of its historical catalog: another
currently active owner-authorized device must re-endorse the complete inventory
with independent CAS before normal browsing resumes. The UI never silently
accepts an old, revoked signer or lets unpinned network state increase the
local head.

## Manual private listing on a receiving device (DEV)

The separate manual delta control plane can now list filenames **only in the
receiving browser**, after the user opts in, imports independently pinned
owner/witness/CAS trust, anchors an exact signed catalog head and imports a
32-byte AES-GCM metadata key. It performs a **fresh complete signed catalog
readback** and requires the exact previously anchored sequence/digest before
decrypting any row. Each AES-GCM authentication tag binds the scope, opaque
object ID, revision and epoch. A wrong key, altered row, stale/forked head,
revocation or logout refuses the entire listing, not a partially trusted list.
The key is imported non-extractable for decrypt only. Names are placed into DOM
text nodes, cleared on logout/close and before other delta operations, and are
never serialized into the exported opaque delta or any Root.ark HTTP request.

This is **not** automatic sync, durable server-side application of names,
change conflict resolution, rename/move/trash, or proof of cloud persistence.
Only the independently signed, append-only opaque catalog is inspected; no
unknown legacy corpus or remote deletion becomes authorized.
