# Root.ark #65 — owner checkpoint persisted in real browser IndexedDB

**NON-PRODUCTION CLIENT-ONLY PERSISTENCE; NOT AN INDEPENDENT HARDWARE
ROOT OR A PERMISSION TO RELEASE PROTECTED CONTENT.**

This opt-in module extends the signed checkpoint primitive originally
implemented under `a542c77` (subsequently amended in the shared branch)
with `public/client/rootark-zk1-owner-checkpoint-indexeddb.js`.
It uses a dedicated IndexedDB database and one object store, containing
only public Ed25519-signed owner checkpoint wire records, not plaintext,
file CEKs, signing private keys, or password/recovery secrets.

## Local protocol

- `bootstrapOwnerCheckpoint` is an explicit one-time operation that
  requires a verified **sequence-1** owner-signed checkpoint and refuses an
  existing record. There is **no** automatic recovery or trusted reset when
  a record goes missing after browser restart.
- `loadOwnerCheckpoint` re-verifies every signed CBOR checkpoint from
  sequence 1 through the retained head, including device/key continuity,
  scope, predecessors, signed revision/digest and stored head digest. The
  optional caller-retained `expectedExternalDigest` must match precisely,
  otherwise it fails closed. This digest MUST come from a trusted external
  owner-held source; a database-supplied value is not such a source.
- `appendOwnerCheckpoint` requires the exact expected previous signed
  checkpoint hash, verifies the complete local chain and the new successor
  outside an IndexedDB transaction, then opens a **readwrite transaction**.
  Within that transaction, before replacing anything, it fetches and
  compares the full latest stored record to the verified snapshot. This
  prevents a concurrent writer from overwriting a different successor
  during the asynchronous WebCrypto proof. All writes are additive;
  the module has no delete, truncate, reset, or destructive migration API.
- The storage format is exact-schema and limited to 512 checkpoints per
  scoped device/signer identity. Browser storage errors or corrupt records
  are denials; object IDs are derived from account, compartment, keyring,
  trusted device ID and Ed25519 key ID. Checkpoints' private verification
  provenance stays in the cryptographic helper's private WeakMap.

## Actual browser test and adverse behavior

Existing `test/issue-65-trusted-device-indexeddb-browser.test.js` uses ONE
disposable Microsoft Edge profile and real IndexedDB implementation with
strict same-origin CSP. The original nonextractable trusted-device recovery
roundtrip still runs. The additional script runs WebCrypto Ed25519
nonextractable owner signing and local persistence through all states:

1. Bootstrap sequence 1; close and reopen an IndexedDB **connection in the
   same browser session** (not a complete browser/profile restart), reverify saved chain
   and compare against a separately saved owner checkpoint digest.
2. Append sequence 2; simultaneously attempt **two different valid**
   sequence-3 successors, requiring exactly one to commit.
3. Replace a stored record's signature by a random value through raw
   fixture-scoped IndexedDB and verify denial.
4. Replace the entire stored chain by an earlier **genuine signed** record,
   setting the corresponding old head digest, and verify denial against
   the separately retained newer owner checkpoint digest.
5. Restore the original verified record, reverify successfully, and
   explicitly delete the **test-owned database only**; reopening with
   the retained newer floor denies the silent reset.

The Edge process/profile are created only for this deterministic test and
cleaned up by the already existing test-owned lifecycle. No current user's
browser storage, credentials, or production data is accessed.

## Explicit limits and NO-GO

IndexedDB is **not** tamper-resistant against same-origin JavaScript,
malicious application deployments, an overprivileged browser profile
operator or whole-profile rollback. A user holding only the IndexedDB
copy cannot prove that all local state was reset. Signature validation
does not authenticate a candidate fresh witness head: the independently
signed CAS/witness history must be checked separately. The module does not
connect to real product login/recovery UI, create independent operator
CAS/witness authorities, distribute durable high-water attestations
between physical hosts or fence remote sockets, WebDAV, sync, versions,
backup/restore and provider effects. It intentionally returns
`independentRollbackProof:false` and `authorizesProtectedIo:false`.
Nor does it authorize a delete/cutover of legacy plaintext.

All release and migration gates remain **NO-GO** pending the full #65.
