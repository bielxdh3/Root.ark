# Root.ark #65 — linked cryptographic approval and durable nonce lab

**Status: NON-AUTHORIZING LOCAL EXPERIMENT. Not a protocol-approved wire type,
normal application route, ciphertext publication, migration or live CAS gate.**

`src/services/zk1ExperimentalApprovalCryptoReplay.js` connects two previously
separate pieces of laboratory evidence:

1. `inspectZk1CiphertextApprovalHeadPreflightV1` checks a deterministic-CBOR
   Ed25519 ciphertext-device-approval candidate against **verified signed v2
   manifest history** and an independently pinned **but caller-supplied**
   nonce-bound witness receipt. Signer must be listed as active **in that
   historical signed head**, with exact epoch, key, scope, object, root,
   manifest revision/digest and nonce. That inspector always reports
   `authorizesRelease:false` and `liveAuthorityVerified:false`.
2. Only after that inspection succeeds does the wrapper decode the same
   signed approval and witness bytes, derive the exact device key ID, signed
   expiry, manifest digest/revision and witness sequence, then call the
   independent disposable PostgreSQL replay ledger. The wrapper copies
   caller-owned binary views and Ed25519 public keys **before its first
   await**, so subsequent mutation cannot redirect the SQL tombstone.
   PostgreSQL reserves the scoped nonce under a unique primary key with an
   exact restricted SQL role and explicit COMMIT. A duplicate or uncertain
   connection result denies. No software in this lab grants protected I/O.

The returned object is always
`{historicalCryptographicLinkVerified:true, replayTombstoneCommitted:true,
freshLiveAuthorityVerified:false, authorizesRelease:false,
protectedIoAdmission:false}`. It is not proof of current device authorization
or independent live witness/CAS state. It cannot be used to publish, read,
download, migrate, restore or claim full #65 acceptance.

## Validation and disposable cleanup

`node lab/issue-65-packet-b/run-approval-replay-postgres.js` creates one
labeled isolated loopback PostgreSQL 18.6 container. The runner now confirms
the **exact Docker container ID plus both fixture labels**, verifies the
PostgreSQL data volume is the **single anonymous** `/var/lib/postgresql`
mount, calls `docker rm -f -v <exact verified ID>`, and confirms that exact
volume no longer exists. It never enumerates/cleans unrelated prior volumes,
named volumes, other Docker resources or real data. Earlier experimental
runner invocations with `docker rm -f` might have left anonymous fixture
volumes; their provenance is not sufficient to delete them retroactively.

The targeted real PostgreSQL tests cover authenticated historical approval
consumption, exact nonce replay denial, separately signed invalid signer and
wrong-object rejection before SQL effect, signed-witness nonce/root
substitution, mutation of caller buffers mid-verification, SQL restricted
roles and column privileges, independent Node OS processes racing the same
nonce, persisted tombstones after fresh processes, expired candidates,
commit-before-ACK uncertainty, and blocked inherited SQL transactions.
There is also an adversarial test for a **correctly signed** approval from a
device explicitly revoked in a later verified manifest: crypto inspection
rejects it and the test asserts the replay SQL service is never called.

**Final focused validation:** Windows native Node **14/14 PASS** plus WSL
Node 22 **14/14 PASS** on the exact real PostgreSQL 18 container; zero skips,
zero failures; `APPROVAL_REPLAY_LAB_CLEANUP verified=true` now includes the
anonymous data-volume deletion check. These local tests do not prove a
malicious host/DB administrator cannot delete tombstones or restore an old
snapshot, and do not substitute for a real independent online witness.

## Remaining normative gates

Issue #65 cannot authorize protected content until the device approval wire
type is formally accepted, signing keys and trust roots are provisioned
outside the application, client-device active/revoked state is independently
fresh with an owner-pinned high-water, independent CAS and witness issue
linearizable live proofs, the nonce ledger and actual client/server/provider
I/O use one atomic authority decision, and all remote physical transfers
(PUT, GET, egress, sync/WebDAV, backup/restore, cloud providers) are fenced
through actual verified process and effect boundaries. PG alone cannot
establish those properties. **PRODUCTION NO-GO.**
