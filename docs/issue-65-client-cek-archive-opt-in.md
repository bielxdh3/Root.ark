# Issue #65: opt-in browser CEK archive (development)

`public/client/rootark-zk1-client-cek-archive.js` is a standalone UMD/CommonJS
adapter. It is deliberately not wired into normal ZK writes or production.

## Inputs and guarantees

Call `RootarkZk1ClientCekArchive.openCekArchive({...})` with these **explicit**
dependencies (no defaults for privileged authority):

- `indexedDBImpl`: real browser `indexedDB`, database
  `rootark-zk1-encrypted-cek-archive-v1`; local atomic readwrite CAS.
- `recoverySecret`: a **user-held independent 32-byte secret**. The adapter
  derives a nonextractable AES-256-GCM key using fresh HKDF salt per archive.
  Neither this secret nor raw CEKs go to the server. Supply it again on restart.
- `ownerPublicKey`: owner Ed25519 WebCrypto verify key with an independently
  stored `independentOwnerSpkiSha256` (32 bytes). `ownerSigningKey` is required
  for writes and receipts; supply `null` for read-only recovery.
- `pinnedCurrentHead`: independently verified `{revision,digest,epoch}`
  (`digest` as 32 bytes); `signedDeviceGrant`: owner-signed current grant. The
  adapter validates owner signature, scope, head, enrolled epoch and revocation
  at open. `assertLive()` must synchronously recheck the session/current owner
  authority on every operation; false/throw closes access.
- `pinProvider`: independently operated `{ read(): Promise<digest|null>,
  compareAndSwap(previousDigest, nextDigest): Promise<...> }`. Pins are
  43-character canonical base64url SHA-256 values. If this external floor is
  missing, stale or contradictory, the adapter refuses CEK recovery. An
  IndexedDB rollback/whole-profile restore alone cannot satisfy this floor.
- `backupProvider`: `null` (local-only) or independent
  `{ put({key,ciphertext}), get({key}) }`. `key` is the exact SHA-256 digest of
  the signed archive; `ciphertext` is UTF-8 bytes containing **only** signed
  AES-GCM sealed CEK entries and opaque identifiers. `get()` returns
  `{ciphertext,receipt}`. For configured backup, supply pinned Ed25519
  `backupReceiptPublicKey` and its independent
  `independentBackupReceiptSpkiSha256`; otherwise both must be `null`.
  The receipt fields must be exactly `{schema,digest,byteLength,providerId,signature}`,
  where `schema` is `rootark-zk1-client-cek-backup-receipt/v1`, `providerId` is
  a 16-byte base64url ID, and Ed25519 signs
  `UTF8("Root.ark/zk-1/cek-backup-provider-receipt/v1\\0") || UTF8(JSON.stringify({schema,digest,byteLength,providerId}))`.
  Backup accepts uncertain PUT ACK only when signed GET/readback returns the
  complete expected bytes and digest.

`archiveKeys({challenge,entries})` accepts the lifecycle challenge with
`{objectId,action,epoch,nonce,entries:[{revision,versionId,ciphertextDigest}]}`
and matching entries `{metadata,revision,ciphertext,cek,state}`. Each CEK **must
be a 32-byte `Uint8Array` or `ArrayBuffer`**. It returns the lifecycle-compatible
owner Ed25519 `signatureBase64` over the existing logical-trash receipt domain,
plus `localIndexedDbCommitted`, `externallyPinnedDigest`,
`remoteCiphertextReadbackVerified`, and
`independentCloudDurabilityProven:false`. An archived CEK is returned as a
**nonextractable WebCrypto `AES-GCM` CryptoKey** via
`readArchivedCek({objectId,revision,versionId,nonce})`. Old version entries
are retained when new generations are appended; mutation of an existing CEK,
metadata or ciphertext digest fails closed.

For a lost pin ACK, use `inspectPendingArchive()` to obtain the verified
candidate digest **without releasing keys**, then
`reconcileUncertainArchive({expectedDigest})`. After IndexedDB/profile loss,
`restoreFromBackup({expectedDigest})` requires the independently pinned exact
digest, verifies the remote signer/receipt, signed archive, AEAD and current
owner/grant, and atomically restores local storage. The owner private key is
not needed on the restoring device.

## Two-browser-device and lifecycle integration

`syncFromBackup({expectedDigest})` imports the independently pinned newest
archive into a second browser's separate IndexedDB database, or advances a
stale first browser after the second writes. It validates the signed provider
GET, Ed25519 owner signature, AEAD, monotonically linked sequence and every
intermediate signed predecessor archive (up to 64 records), stopping only at
an independently verified local digest or genesis. It rejects missing history,
forks, rollback, stale pins and differing epoch. This is an explicit operation,
never an implicit trust upgrade during a CEK read. The second device must have
its own current owner-signed device grant and user-held recovery secret.

For `renameOrMoveCommitted`, inject `cekArchive:
store.createRenameArchiveBridge()`. Its `write` AEAD-seals the transient raw32
destination CEK before the file's remote PUT and returns a 43-character signed
archive digest; `read` requires that exact independently pinned receipt and
checks the signed ciphertext digest and full metadata. It releases a temporary
32-byte copy *only* to the existing rename composer, which compares and zeroes
it before PUT.

For `rootark-zk1-client-logical-trash`, inject the callbacks from
`store.createLogicalTrashBridge()` as `archiveKeys` and `readArchivedCek`, and
use the same independently pinned owner public key as
`archiveAuthorityPublicKey`. The bridge binds the exact owner scope in its
challenge, returns precisely `{signatureBase64}` for the lifecycle verifier,
and restores nonextractable operational CEKs. Existing nonexportable source
CEKs can be proven against a *previously* encrypted raw CEK by an authenticated
AES-GCM challenge; unknown source CEKs remain blocked. The new tombstone CEK
is randomly generated on the client, immediately imported nonextractable for
AEAD operations, and its raw32 is wiped after authenticated archive readback
before any ciphertext PUT. Tombstone and restored revisions stay in the
encrypted historical archive; permanent erasure is outside this bridge.

## Owner rotation and recovery on another browser

The newly authorized owner (new Ed25519 key, independently pinned SPKI, new
current signed device grant, higher owner revision **and** epoch) calls
`rotateFromPreviousOwner({transition,previousOwnerPublicKey,
independentPreviousOwnerSpkiSha256,previousRecoverySecret})`. The transition
is a strict object with fields `schema,scope,fromOwnerSpkiSha256,
toOwnerSpkiSha256,fromHead,toHead,previousArchiveDigest,nonce,
fromSignature,toSignature` and schema
`rootark-zk1-client-cek-owner-rotation/v1`. Both owner signatures authenticate
the eight unsigned fields with the Ed25519 domain
`Root.ark/zk-1/cek-owner-rotation/v1\0`. The adapter verifies the old signed
archive against the external old floor, decrypts privately, re-encrypts all
historical CEKs under the new recovery secret, signs with the new owner,
requires signed remote GET/readback and moves the external CAS floor.
`adoptRotatedOwner(...)` lets an old device holding the old signed local archive,
or an empty new device, verify the same two signatures, both AEAD plaintext
histories and old-to-new signed predecessor edge, and adopt the new signed
archive only when the new digest is independently pinned. There is no automatic
credential or trust-anchor transfer; explicit owner authorization and current
device grant are mandatory.

These operations prove client cryptographic continuity and readback relative to
the injected external provider. They do **not** attest cloud-host independence,
provider retention, atomicity across IndexedDB and external CAS, or physical
durability. If local storage committed but the external CAS failed, CEK release
stays blocked until explicit reconciliation. Post-CAS external crash recovery
and remote provider custody remain provider-operational responsibilities.

## Explicit boundaries

- Existing lifecycle `generateFileCek()` returns a **nonextractable CryptoKey**.
  WebCrypto cannot export or AES-wrap a new key. The adapter refuses a new
  nonextractable CEK without pre-existing authenticated raw32 escrow. For
  tombstones the client generates raw32 first and imports the operational
  CryptoKey nonextractably; for rename the committed composer already does so.
- A successful IndexedDB transaction is **local browser persistence**, not an
  independently durable cloud backup. A signed remote GET/receipt proves only
  what that endpoint returned, not physical cloud replication or retention.
- `assertLive` and `pinProvider` are required independently trusted injection
  points. In particular, the caller must establish current signed owner
  history, current grant/device possession, reauthorization and revoke fences;
  a historical signed grant alone is not ongoing device proof of possession.
- A caller or malicious same-origin script with the live user-held recovery
  secret can decrypt CEKs. Javascript memory and browser profile confidentiality
  remain platform/security assumptions. There is no global completeness proof,
  production cutover, default enablement, remote deletion or automatic egress.

## Targeted validation

Run `node --test test/issue-65-client-cek-indexeddb-archive.test.js` on Node 24.
For actual Edge IndexedDB and page-reload recovery, run
`node test/support/issue-65-cek-edge-manual.js` on Windows with Edge installed.
The Edge test uses an isolated temporary browser profile and synthetic keys.
