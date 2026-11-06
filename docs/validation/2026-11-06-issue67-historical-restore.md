# Issue #67 — signed historical file restore (draft)

This branch extends the read-only history API in PR #253 and history CLI in PR #260. The Sync v2 CLI now accepts:

```text
node sync-client/rootark-sync-v2.js restore --config <private-config> --object-id <id> --version-id <id>
```

The ordinary private Sync v2 configuration and **in-memory** `ROOTARK_SYNC_FILE_KEY`, `ROOTARK_SYNC_DEVICE_PRIVATE_KEY` and `ROOTARK_SYNC_DEVICE_PUBLIC_KEY` are still required. The command does not print plaintext, signing keys, bearer credentials or ciphertext. It returns the newly created operation and version IDs, along with `pushed`/`pending` status.

The operation uses existing `SyncEngine.restoreHistoricalVersion`, the authenticated `/sync/v1/objects/:objectId/history` endpoint, the current signed object head, `verifyIncomingOperation`, AES-GCM/AAD and the existing file-key policy. The selected historical ciphertext is decrypted in the local client, never on the server. The client creates a **new** Ed25519-authorized `update` with fresh operation ID, version ID and revision and the current head as CAS base revision. Signed journal enqueue precedes local filesystem materialization. The existing outbox and server atomic device registry decide remote admission; the historical operation is never replayed as a write. Historical MOVE content is authenticated and unpacked before restoration.

Safety boundaries: the client rejects missing/duplicate/tombstoned history versions, foreign objects, current-head/history disagreement, unauthenticated or expired historical proofs without separately trusted evidence, unavailable old-epoch keys, directory versions, excluded paths, and collisions with untracked or different local data. An existing tracked file must still match its last-synchronized SHA-256, checked before and after asynchronous signing, so unsent edits and unsent local deletion are not silently replaced by recovery. If remote push is offline, the command reports `pending: true`, not remote success. Readback equality is checked after an acknowledged push.

## Local evidence (2026-11-06)

RED: `test/issue-67-historical-restore.test.js` failed before `restoreHistoricalVersion` and before the `restore` CLI existed; a later RED caught MOVE's historical `sourcePath` and encoded payload handling.

GREEN: `node --test test/issue-67-historical-restore.test.js` — 7/7 PASS on Windows Node 24. Includes a disposable *real* `SyncObjectStore({ atomicDeviceRegistry: true })`, enrolled Ed25519 device, durable 2→3 version transition, physical JSON reopening and exact restored local bytes. Other cases cover revoked signer, invalid signature/ciphertext, unknown version, foreign current head, collision with an untracked local file, and MOVE payload decoding. The first independent review exposed a real P2: unsent edits in an already tracked local file were staged into trash and overwritten; a focused new RED reproduced it, followed by GREEN denying the restore before journal enqueue/remote push. `test/issue-67-history-client.test.js` retains 3/3 PASS for real Express owner/tenant/permission boundaries.

This is **not** certification of an independent production historical witness, off-host custody, production provider durability or ZK global cutover (R1). Historical proofs beyond their validity window require the existing independently provisioned physical historical-admission provider; standalone CLI configuration alone cannot manufacture it. Old key epochs require an authorized key policy and are deliberately rejected by the current single-epoch client. This branch does not complete every Ransomware Shield acceptance criterion in issue #67, nor does it authorize merge or deploy.
