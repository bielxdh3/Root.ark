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
The import API takes an opaque `ownerTrust` capability returned by
`prepareOwnerBackupImportTrust`, not `trustedOwnerPublicKey`, `trustedRoot`,
or `trustedEpoch` from the archive. Preparation requires the owner Ed25519
public SPKI and its **separately retained external SHA-256 fingerprint**,
an owner-signed history checkpoint, and a corresponding owner-signed ciphertext
root checkpoint. It verifies both signatures with the fingerprint-pinned key
and binds the exact compartment, object, epoch, manifest revision and digest,
and ciphertext root. A verified `previousHistoryProof` from the local owner
checkpoint ledger must be passed when a previous checkpoint exists. The
history signature must extend that head; a stale or unrelated head fails
closed. The source of the external pin is a **caller trust obligation**: an
archive or untrusted server cannot be permitted to provide the fingerprint
and public key together. There is no automatic trust-on-first-use or owner
enrollment in this API.

The original
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
copy proof. The caller must fetch the external owner SPKI fingerprint and
monotonic history floor from a previously trusted source **outside the archive**;
this module cannot establish their provenance or detect a rollback if all
locally retained copies of the checkpoint were erased. There is no product
keychain/bootstrap, persistent ledger integration in this import flow, or
owner-approved recovery ceremony here. The ephemeral signature does not prove trusted device
enrollment, backup availability or externally durable replication. It does not
restore object version history, trash/tombstones, compartment authority, a
lost CEK, a recovery package or user access. It does not authorize recovery,
restore, release or migration cutover. Historical revisions beyond 1, epoch
rotation and reencryption require separate reviewed workflows. The backend's
test-time disposable witness provider does not establish a deployed independent
production authority.

The focused real HTTP suite validates owner forgery/missing owner, SPKI
fingerprint substitution, root/history signature tampering, authentic signed
root from a different object, prior signed history floor, epoch rollback,
plaintext leak, scope/manifest mismatches, old signatures, ciphertext
substitution, pending witness, revoked device, forged/replayed GET, duplicate
PUT, lost PUT acknowledgement and actual client-only CEK decrypt following
readback on the authorized path. The UMD module load was tested in a restricted
VM; **no Edge/IndexedDB end-to-end UI restore was validated**.
