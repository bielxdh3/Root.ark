# Issue #65 — browser owner-signed ciphertext import boundary

The browser-only `RootarkZk1OwnerBackupImport.importOwnerSignedBackupCiphertext`
copies an **existing encrypted first version of an otherwise absent object** to
the actual `/zk-1/v1/content/put` endpoint and reads the new revision back via
`/zk-1/v1/content/read`. The client does not transmit a CEK, plaintext or the
encrypted filename as plaintext. The receiving backend must independently
enforce the active signed manifest, device signature, epoch and fresh witness
gate. The client checks integrity and owner intent **before any network I/O**.

The owner intent profile is
`rootark-zk1-client-backup-import-authorization/v1`. Its signature is Ed25519
over UTF-8 `Root.ark/zk-1/client-backup-import-authorization/v1\0` followed by
`JSON.stringify(unsignedFields)` with exactly this key order:

`schema, account_id, compartment_id, keyring_id, object_id, version_id,
epoch, source_revision, manifest_revision, manifest_digest, expires_at,
ciphertext_sha256, ciphertext_root`.

The authorization object includes these fields plus `signatureBase64`.
Opaque identifiers and SHA-256 digests are canonical unpadded base64url;
the root uses `RootarkZk1CiphertextRoot.computeCiphertextRoot([ciphertext])`.
The signer must be an independently pinned Ed25519 owner verification key,
not a key supplied by the backup archive or Root.ark server. The original
`rootark-zk1-file-v1` envelope must carry the exact signed scope, object ID,
version ID and epoch, with `parent_version_id: null` and `kind: file`.

Only `source_revision: 1` is admitted, and the owner signature binds the
**current** recovery manifest revision, SHA-256 digest and a short expiry
(at most 45 seconds after the current device authorization timestamp).
The signed device PUT must be `expectedObjectRevision: null`; existing objects,
lost acknowledgement and replay must fail closed. Success requires a second
signed historical GET, exact SHA-256 and chunk-root readback. No secret key is
stored in this importer, and any subsequent local decryption requires a CEK
already held by the authorized client.

**Security limitation:** this profile is a bounded, experimental ciphertext
copy proof. Its owner verification key and root must be independently pinned
by the caller; there is no product keychain/bootstrap or owner-approved
recovery ceremony here. The ephemeral signature does not prove trusted device
enrollment, backup availability or externally durable replication. It does not
restore object version history, trash/tombstones, compartment authority, a
lost CEK, a recovery package or user access. It does not authorize recovery,
restore, release or migration cutover. Historical revisions beyond 1, epoch
rotation and reencryption require separate reviewed workflows. The backend's
test-time disposable witness provider does not establish a deployed independent
production authority.

The focused HTTP suite validates owner forgery/missing owner, plaintext leak,
wrong root/epoch/scope/manifest, old signatures, ciphertext substitution,
pending witness, revoked device, replay, lost PUT acknowledgement and actual
client-only CEK decrypt following readback on the authorized path.
