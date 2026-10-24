# Issue #65 — independently signed V2 checkpoint readback (restricted DEV slice)

**Scope:** isolated developer review branch rebased onto published `f00f948`; **not** a production witness gate and not a deployment. This branch contains the previously private readback experiment `5457889` plus corrections for independently reported operation-fork and higher-sequence rollback bypasses. The separate private checkpoint START/RECOVER/FINISH admission work is **not** integrated here and remains under P1 review.

## What is actually enforced

`src/services/zk1V2CheckpointRemoteFloor.js` maintains one independently pinned V2 terminal high-water in its own private SQLite database, using WAL/FULL and a separate Ed25519 signer. An advance requires **both** independently signed `FINALIZED` CAS and FLOOR V2 receipts authenticating the same account/compartment/keyring, operation, sequence, head/checkpoint digest, distinct signer identities and status. An additional out-of-band pinned *static owner* Ed25519 signature covers the exact scope, sequence, claimed owner epoch, previous/final head and checkpoint digests and hashes of both receipts. The floor accepts only contiguous advancement from its current predecessor, and verifies the full bounded signed history on each nonce-bound signed readback. Reusing an identical terminal receipt pair is idempotent; skipping/replacing a predecessor or changing epoch/digests fails closed.

`src/services/zk1V2CheckpointFloorHttps.js` exposes only two separate TLS 1.3/mTLS endpoints with an exact allowed certificate fingerprint: `/v1/floor/advance` and `/v1/floor/head`. A bare HTTP `advance` success is **never** trusted as evidence. The caller obtains a fresh random-nonce Ed25519-signed readback under an independently pinned floor public key, scope and retained monotonic minimum `(sequence, chainHash)`. A missing/wrong server TLS pin, client mTLS grant or floor Ed25519 key denies. An externally retained minimum, not the restarted floor database alone, prevents a reverted database from reopening as the accepted latest state.

The existing V2 coordinator (`zk1OpaqueCheckpointV2Remote.js`) now accepts **optional** `requiredV2FloorClient` of the concrete pinned HTTPS client type. With that protected option, its `publish/reconcile`, `readConsistent` and `predecessorEndorsements` **must** additionally read this third independent signed terminal head and match exact V2 final sequence, authenticated CAS/FLOOR head/checkpoint digests, signed catalog-header owner epoch, the exact 32-byte **operation ID**, and canonical nonce-independent identities of **both verified FINALIZED CAS/FLOOR receipts**. A fork carrying the same seq/epoch/digests with a different operation/receipt cannot pass. Any stale, offline or mismatched floor aborts the protected operation. This check is deliberately after CAS and FLOOR `FINALIZED`: it does not claim a distributed checkpoint write lock or automatically advance the owner-held independent floor. On partial completion the caller must retain PENDING/uncertainty, submit authentic owner-approved floor advancement separately and retry reconciliation. Existing callers omitting the protected option retain their earlier explicitly non-production legacy behavior; they are **not** covered by this gate.

## Signed ancestry and externally retained minimum

The original readback verifier accepted any validly signed head of sequence
`N+1` above a locally pinned minimum `N`, *without proving that `N` was an
ancestor*. A separate independent review reproduced both this rollback/fork
and a same-sequence different-`operation_id` coordinator bypass. The new
head wire format signs operation ID, both receipt identity hashes and a compact
sequence of owner-Ed25519-signed advance statements. A client must supply its
independently retained minimum `(sequence,chainHash)` in **every** mTLS head
request; it recomputes the entry hash chain from that exact minimum, validates
owner-signed continuity, epoch, head/checkpoint digests and receipt bindings,
and only advances its in-memory minimum after the complete signed proof passes.

**Fail-closed scope limit:** the proof window is capped at **8 successor
events** per readback, not an invented scalable Merkle accumulator. Larger
gaps refuse readback; the client must acquire individually verified contiguous
intermediate anchors through a later paged protocol, never simply reset its
minimum. Historical owner key rotation also remains restricted to the
independently pinned static owner signer; transitions requiring a different
historical signer cannot yet be verified from this module alone. This slice
must NOT be advertised as 100% V2 lineage, distributed admission, or production GO.

## Executable evidence

`test/issue-65-opaque-checkpoint-v2-remote-mtls.test.js`, with `ZK65_V2_INDEPENDENT_FLOOR_MTLS=1`, runs an actual disposable child process (`test/support/issue-65-v2-checkpoint-floor-child.js`) with a separate SQLite WAL, Ed25519 key and real HTTPS/mTLS listener alongside the existing real V2 CAS and FLOOR HTTPS servers. It verifies a legitimate #128→#129 publication, independent terminal grant/advance and signed readback; rejects stale head and early `reconcile`, wrong client certificate, wrong Ed25519 pin, forged owner signature, incorrect signed predecessor, remote offline during protected reads/reconciliation; restarts the OS child with its persisted SQL and retained minimum; then deletes the event row **from the disposable test floor only** to show that bootstrap below the retained signed floor fails closed. Unit tests separately reject nonce replay, wrong key, mismatched scope/epoch/sequence and monotonic floor regression on Node 22/24. When `ZK65_NODE22_BINARY` points to a compatible Node 22 executable, an additional independent Node 22 OS child performs **real TLS 1.3/mTLS readback verification** of the Node 24 floor process (`test/support/issue-65-v2-floor-readback-client.js`); this is not equivalent to running SQLite floor-server native addon tests on Node 22.

## Remaining DEV P1/P2 boundaries — not solved

- **No cross-host physical evidence.** The lab is two OS processes and distinct files/keys on **one host** using loopback mTLS. The network endpoints can be deployed on separate hosts in a future experiment, but this run does not test power-loss, remote fsync, physical host independence, cluster consensus or compromised-host custody.
- **No atomic CAS/FLOOR/witness admission.** The independent floor advances **after** both V2 `FINALIZED` receipts and only gates protected *post-finalization* readback. There is a gap after CAS/FLOOR SQLite commit and before independent floor advancement; no shared CAS/fence generation, atomic quorum commit or prevention of an uncooperative writer bypassing an optional protocol. This must not be used as a remote writer authorization or proof of completed physical writes.
- **Owner rotation remains unresolved.** This floor's owner signing key is an independently configured, static trust pin. It does not yet verify a fresh owner device/recovery history when granting a new terminal advance, nor enforce owner revocation/epoch rollover, a distributed trusted configuration generation, or V1→V2 owner historical replacement. A compromised or revoked private key might sign future floor events until bootstrap policy is securely rotated. CAS/FLOOR terminal receipts alone do not solve this.
- **Rollback minimum is an external obligation.** The client now requires an explicitly pinned minimum and independently pinned owner key, and verifies ancestry when the signed sequence increases. The caller must preserve the latest signed `(sequence, chainHash)` outside the floor database and attest its identity on restart; if the same hostile operator can replace both database **and** its retained minimum/keys, a rollback can still be hidden. Bootstrapping the public key from a child process IPC response in this **test** is not independent production key distribution.
- **Outstanding worker8/worker9 P1 review.** The private DEV checkpoint `RECOVER`/`FINISH` workflow may permit premature release of an `ACTIVE` admission without a durable physical write stop. That code is neither in the published `e1c0356` base nor changed here. **No conclusion about distributed admission safety** follows from this proof-of-readback slice.
- **Limits and data safety.** Full-history verification is deliberately capped to 4096 rows. Test files and generated credentials are disposable. The demo neither uploads ciphertext to real cloud providers nor promises external durability, external witness monotonic custody or production-safe key management. Overall issue #65 remains **NO-GO** for production, merge/deploy not authorized.
