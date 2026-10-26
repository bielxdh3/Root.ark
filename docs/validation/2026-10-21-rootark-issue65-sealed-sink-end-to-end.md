# Root.ark #65: trusted ciphertext upload staging versus sealing

**Status: PARTIAL / EXPERIMENTAL; no production route switched.**

`src/services/zk1SharedPgCiphertextSink.js` now has two deliberately distinct
interfaces. `put(...)` uploads bounded ciphertext chunks as **staged bytes
only**; its `{chunkCount}` result does not authorize treating the object as
complete. `putSealed(...)` requires an externally owner/device-authenticated
32-byte `expectedRootHash` and exact `expectedChunkCount`, then requests
`sealCiphertextObject()` using the SAME live worker, admission ID and gate
generation. A reply succeeds only after a strict `{status:'SEALED',chunkCount}`
acknowledgement from the pinned gate. A missing or uncertain ACK is retried
with the same root and identity, never as a new worker. FINISH runs on both
success and failure. An invalid root, missing chunk, failed commit,
generation change or revoked worker is not reported as a sealed upload.

Input scope/digest/worker bytes and the root are snapshotted before the first
await. Every external async adapter call receives **fresh copies** so a
mutating adapter cannot change the authoritative operation or redirect a
subsequent physical write. This does not turn an untrusted caller into an
owner: the separate gateway must validate signed keyring, scope, object,
device authorization and commitment **before** calling `putSealed`.

The opt-in real PostgreSQL laboratory executes the trusted sink through
an actual restricted `zk1_gate_runtime` SQL login, confirming encrypted
chunk writes, durable sealed object root, worker FINISH and the following
quiesce→pending transition. It also exercises network mTLS and independent
signed witness tests from the shared runner. The shared disposable PG lab
passed **23/23 tests**, exit 0 and verified labeled resource cleanup in this
snapshot, including fail-closed fake adapters and mutation regressions.

**Not proven**: client/device signature validation at this API boundary,
normal upload/download/WebDAV/sync/backup routes, physical read egress,
S3/Google Drive/remote-provider fencing, a fully atomic CAS+witness+gate
transition, and owner-approved reversible migration. These still block
issue #65 acceptance; staged bytes must not be published as protected content.
