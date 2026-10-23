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

## Explicit boundaries

- Existing lifecycle `generateFileCek()` returns a **nonextractable CryptoKey**.
  WebCrypto cannot export or AES-wrap that key. This adapter refuses it;
  integration requires minting a recoverable 32-byte CEK under client control
  and immediately importing the operational copy as nonextractable, or a
  separately reviewed custody primitive. The module does not alter W5/W6.
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
