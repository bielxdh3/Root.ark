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

## Owner-witnessed logical trash (DEV; additive only)

The manually anchored normal-browser delta control now supports a **single**
logical trash for an existing current object/version. The user separately
supplies a non-extractable AES-GCM metadata key with encrypt+decrypt usage,
an exact offline-pinned CAS floor, a current owner-signed device grant, and
independent witness/CAS authority. The browser verifies current signed catalog
pages and decrypts the preceding metadata locally; if already trashed, or a
revision/epoch/key/CAS floor conflicts, it refuses **before** write. It then
signs an Ed25519 statement naming the encrypted predecessor digest and metadata
digest, exact precommit CAS sequence/digest, scope, device, revision, epoch,
owner head and one-use nonce. The statement and signature are encrypted with
AES-GCM under a domain-separated AAD before they cross the protected HTTP
boundary. A separate encrypted metadata marker identifies the new append-only
tombstone row **inside the browser only**. Generic version publishing cannot
select this marker.

The existing durable local intent → single protected PUT → exact signed GET →
one CAS commit/readback → journal confirmation remains the sole publication
path. No DELETE endpoint is invoked and all old ciphertext versions remain
in the signed catalog and recoverable through their original historic exact
GET. A second authorized device can opt into checking the signed tombstone:
fresh current owner/witness/CAS and full catalog, AEAD open, Ed25519 signer
signature, previous CAS link, parent metadata/ciphertext digest, historical
version retention and a final signed head readback are all mandatory. Fork,
revoked grant, wrong metadata key, tampered signed tombstone, stale head and
second trash attempt fail closed. UI never renders encrypted internal marker
as a filename; the name/key/operation class are never posted as plaintext.

The tombstone is **logical only**; it is not physical deletion, GC, provider
durability proof, restoration of a trashed file, rename/move or general
bidirectional sync/conflict convergence. Uncertain PUT/CAS intentionally
requires independent reconciliation, not an automatic retry.
The signer grant is verified against the externally pinned owner's Ed25519 key,
current scope/manifest/epoch and live witness; duplicate or revoked signer
grants are rejected. Publication binds the originally signed CAS sequence and
digest to the immutable pre-PUT journal, and requires a newly authenticated
signed tombstone readback before clearing that journal.

After later unrelated catalog commits, historical tombstone verification asks
the independent CAS authority for the **exact historical sequence** and checks
its nonce-bound, freshly signed `rootark-zk1-opaque-catalog-snapshot-fetch/v1`
envelope against the *current* pinned CAS head, owner-signed historical catalog
header and every immutable encrypted row. The manual browser form offers an
optional independent **snapshot URL**; the browser sends POST JSON
`{scope, nonceBase64, sequence}` without cookies and requires canonical signed
CBOR with the independent CAS key. If the snapshot endpoint is unavailable or
does not match the current signed head, historical inspection fails closed.
Inspection of a tombstone created under an older epoch remains fail-closed
without the separately signed historical signer/epoch proof and active-device
catalog re-endorsement described below. Encrypted historical versions are
**not** removed.

## Historical tombstones across a signed owner epoch rotation (restricted DEV)

The read-only historical path now accepts a **separately supplied** complete
owner-signed epoch-head sequence, from manifest revision 1 through the current
witness-pinned revision (maximum 128; no rollover). Each entry has exactly
`{schema,account_id,compartment_id,keyring_id,revision,manifestDigest,epoch,previousDigest,signature}`,
where `schema` is `rootark-zk1-browser-owner-epoch-head/v1`. The independently
pinned owner Ed25519 key signs `Root.ark/zk-1/browser-owner-epoch-head/v1\0`
followed by UTF-8 JSON of the ordered fields excluding the signature.
`previousDigest` is null at revision 1 and otherwise base64url SHA-256 of
`Root.ark/zk-1/browser-owner-epoch-head-hash/v1\0` plus the predecessor's
ordered JSON and its decoded Ed25519 signature. Manifest revisions must be
consecutive, epochs monotone (at most one epoch per revision), and the final
signed revision/digest/epoch must equal the current *externally selected*
manifest that the freshly signed independent recovery witness confirms.
The JSON file contains `heads` and `grants`: each historic signer grant is
separately signed by the owner and must match the precise historical manifest
revision/digest, epoch, device ID and scope. A grant only proves authorization
**at that historical revision**; it cannot authorize an operation in a later
epoch, even when its signature was valid before revocation.

A current, unrevoked reader's grant is mandatory for the protected historical
ciphertext GET, and the current catalog head must have been re-endorsed by an
active signer after rotation. The exact old header/rows remain independently
authenticated by the current CAS authority's nonce-bound signed snapshot
(`sequence`, `digest`, `head_sequence`, `head_digest`, pages). The old header's
owner revision/digest/epoch must match the enclosed tombstone's owner claims,
the owner-signed chain and the historical signer grant. The receiving user
imports the historical epoch AES key **only as nonextractable decrypt-only**;
an explicit local array maps one key per epoch and refuses duplicate/missing
epochs. New PUT, tombstone publication, restore and grant issuance still use
only the current owner's verified grant and epoch.

Absent or forged historical owner chain, incomplete grant, wrong epoch key,
unre-endorsed current catalog, offline independent authority, or head number
over 128 are **UNKNOWN / fail closed**; no read/restore is authorized. This
restricted feature verifies the separately owner-issued epoch mapping but does
**not** establish a complete V2 manifest transition proof for every old epoch,
external fsync, any generalized epoch rollover, or automatic migration. The
current repo branch does not include worker-3's separately approved rekey
restore: historical inspection returns `ownerApprovedRekeyRequired: true`, and
does not unlock the generic `commitVersion()` path. Integration with that
separate restore contract must be reviewed before enabling writes.
