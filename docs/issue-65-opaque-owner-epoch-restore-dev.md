# Issue #65: owner-granted opaque restore after epoch rotation (DEV)

This increment restores an **old encrypted file revision** (epoch N) after a
**currently authorized device has issued its signed logical tombstone at epoch
N+1**. It is a manual, explicitly consented, additive operation in the normal
authenticated browser workspace. No server plaintext or physical deletion.

## Required independent evidence

1. A current, **offline-pinned** owner public key and owner-history checkpoint;
   the existing browser trust-floor verifies owner history and revocation.
2. Independently signed **current** owner witness and catalog CAS, with the
   exact catalog sequence/digest pinned outside the server. The writer checks
   the complete signed catalog/epoch, current device grant and protected GET.
3. The original source metadata JSON, prior file CEK (32 raw bytes), and the
   metadata AES-256 key that decrypts the current signed tombstone and previous
   row. These are presented locally; none are sent to Root.ark.
4. Two independently retained, *new* 32-byte keys for the destination epoch:
   the new content CEK and new metadata AES key. Both MUST differ from their
   historical counterparts and each other. Retain them in your offline recovery
   archive; Root.ark does not silently claim they are durably backed up.
5. A freshly **owner-Ed25519-signed** rekey grant identifying the exact current
   signed catalog, tombstone, predecessor, epochs, device, and SHA-256 digests of
   both new keys. The current owner signs it **off server**, only after checking
   the witness/CAS and device's active grant.

Grant domain (UTF-8 with trailing NUL):
`Root.ark/zk-1/opaque-owner-epoch-restore-grant/v1\0`.

Grant canonical JSON properties **in this exact order**, then `signature`:

```text
format, account_id, compartment_id, keyring_id, deviceId, objectId,
sourceRevision, sourceEpoch, sourceDigest, tombstoneRevision, tombstoneEpoch,
tombstoneDigest, catalogSequence, catalogDigest, ownerRevision, ownerDigest,
currentEpoch, destinationRevision, currentCekSha256,
currentMetadataKeySha256, nonce, issuedAt, expiresAt, signature
```

- `format`: `rootark-zk1-opaque-owner-epoch-restore-grant/v1`.
- Digests and nonce: canonical base64url with no padding (32 bytes).
- `sourceRevision`, `sourceEpoch`, `sourceDigest`: first predecessor file
  from the complete signed catalog, **not** client-supplied server flags.
- `tombstoneRevision`, `tombstoneEpoch`, `tombstoneDigest`: latest verified
  tombstone committed under the current epoch.
- `catalogSequence` and `catalogDigest`: exact current independent CAS.
- `ownerRevision` and `ownerDigest`: current witnessed owner history head.
- `deviceId`: the current owner-granted device, also required to have
  **authored** the verified tombstone.
- `currentEpoch`: exactly the witnessed current owner epoch.
- `destinationRevision`: tombstone revision plus one.
- `currentCekSha256`, `currentMetadataKeySha256`: SHA-256 of the two
  user-held raw 32-byte destination keys. The grant stays offline.
- `nonce`: new 32-byte random value; `issuedAt` and `expiresAt`: integer
  Unix seconds, validity window **at most 300 seconds**. Signed receipt must
  not be used against another CAS or after expiry.
- `signature`: base64url Ed25519 signature of
  `domain || UTF8(JSON.stringify(grantWithoutSignature))` with the current
  owner's private key. The browser verifies against the offline-pinned **current
  owner** public key. No self-signed signer or server-returned owner is trusted.

### Write sequence

The client re-verifies the tombstone signature with the **current signed device
grant key**, the signed predecessor and exact historical GET. After local
decryption with the historical CEK, it validates the owner-signed rekey grant
and new key commitments, then re-encrypts locally under a freshly generated
`version_id`, new AEAD AAD and new CEK. The new catalog metadata is encrypted
with the new metadata key. The existing writer persists a signed durable
intent **before** signed PUT, performs exact signed GET, signs/checks catalog
CAS and only then clears the intent. A lost GET/ACK retains the intent and
forbids automatic retry. A generic catalog publish cannot resurrect a
tombstone without this restore-specific verified path.

### DEV limits / explicit NO-GO

- Only old **file content** with a current-epoch tombstone authored by the
  current authorized device. A tombstone signed by an earlier epoch/owner or
  another historical device requires verified historical owner-grant signer
  provenance, multi-epoch chains and a separate implementation; it fails closed.
- The current catalog listing uses a *single* local metadata key. After a
  rekey creates versions under two distinct metadata keys, displaying all
  historical names together requires a separate owner-authenticated
  multi-epoch metadata-keyring and cannot be inferred from server metadata.
- Real external provider durability, independently hosted witness/CAS
  reachability, signed multi-device post-rotation end-to-end execution, and
  destination key archival are not certified by loopback fixtures.
- No production restore, automatic sync, physical deletion or cutover is
  authorized by this DEV increment.

### Oct 24 integration corrections: distinct epoch metadata keys and expiry fencing

- A historical predecessor metadata key is accepted in the restore route only
  as a nonextractable AES-256-GCM **decrypt-only** key. The tombstone for the
  present epoch is verified separately under its own, active AES-GCM metadata
  key. A cryptographic readback of the historical metadata with the current
  tombstone key must **fail**, preventing accidental old-key reuse in new-epoch
  tombstones. The newly written version uses a third, owner-approved metadata
  key bound to the Ed25519 rekey grant and a distinct new CEK.
- The signed rekey grant is copied after exact-field validation, protecting
  the approval from caller mutation during awaits. The timestamp and active
  device/epoch are checked again before journal admission, immediately before
  protected PUT and before catalog CAS, with lost-ACK semantics unchanged.
  A revoked owner or expired grant must never authorize a new mutation; this
  is a client DEV fence, **not** an atomic distributed witness transaction.
- The test fixture now uses distinct historical/current metadata keys, and
  malicious grant fields are **re-signed with the legitimate owner key** to
  test semantic checks rather than merely signature rejection. A controlled
  expiry after historical readback is denied before any PUT. Node/Edge loopback
  is still a local test and the mock writer is not a substitute for independent
  multi-host mTLS, PostgreSQL durability or cloud custody evidence.

### Last-moment CAS admission expiry fence (independent P2 follow-up)

The recoverable writer now accepts an opt-in, synchronous, **true-returning**
`beforeCasAdmission` callback only with a retained signed pending intent. This
callback is invoked **after** authenticated owner/CAS checks and all awaited
ciphertext GET and catalog-signature preparation, immediately before the
single real CAS POST. The normal browser restore supplies its local sealed
owner-grant epoch/expiry/session verification closure. An expired grant aborts
before the actual CAS POST; the already-written immutable PUT and journal
remain conservatively uncertain and MUST NOT be retried automatically.

An adversarial real HTTP/SQLite browser-writer test advances the simulated
grant clock inside the awaited signed ciphertext GET. It verifies the final
admission callback ran, no CAS POST was sent, the signed CAS sequence did not
advance, and the pending intent survives. A separate Edge/loopback fixture
advances expiry inside a mocked commit and verifies the uncertain journal.
This is **not** an atomic multi-host authorization lease: host-side clock
changes, witness revocations after the synchronous callback and untrusted
network delays still require independent authority fencing in DEV.
