# Issue #65 — optional signed-history gate in the protected object store

**Status: local opt-in security increment; not production ready.** The
development protected-content store previously checked a correctly signed
fresh independent witness head and the most recent CAS manifest, then used
that manifest's device table to authorize PUT/GET. A current manifest alone
does **not** establish a complete Ed25519 enrollment/revocation chain.

## Implemented trust boundary

`Zk1ProtectedObjectStore` accepts an opt-in strict mode:

- `signedHistoryRequired: true`;
- `signedHistoryGenesisDigest`: exactly 32 bytes, provisioned from a trusted
  owner-controlled genesis checkpoint, **not** from the current CAS response;
- `verifiedHistoryProvider`: returns an in-process `verifyRecoveryHistoryPublicV2`
  result (with the private verifier brand), not arbitrary JSON or booleans.

Before any plaintext-free protected SQLite read/write effect, the store:

1. Verifies the fresh nonce-bound witness head with its already-pinned Ed25519
   witness key and scope, with an enforced local anti-rollback floor.
2. Confirms the latest CAS manifest is canonical and has the same digest,
   revision, scope and epoch as the signed witness head.
3. Calls the strict signed-history provider. The result **must** satisfy
   `isVerifiedPublicRecoveryHistoryV2`. Unbranded claims are rejected.
4. Requires the proof's signed genesis to hash to the independently supplied
   owner checkpoint. A self-signed replacement genesis is rejected.
5. Requires the proof's latest head revision, digest and exact canonical bytes
   to equal the freshly witnessed CAS manifest.
6. Only then checks the selected device's Ed25519 operation signature,
   active status and epoch, before entering the existing nonce/clock/replay
   transaction and optional witness I/O-admission gate.

**Security correction during review:** The inexpensive rejection-only
device active/revoked and Ed25519 operation-signature checks now happen
*before* downloading/verifying the full signed chain. They do not authorize
access; the branded full chain is still mandatory before any ciphertext
effect. Full-history verification is additionally limited to **two concurrent
checks per local content-store instance**, failing closed when saturated.
This avoids unauthenticated-to-the-device public-history resource
amplification, not a distributed rate-limit guarantee.

When strict mode is selected without a provider, store construction fails
closed instead of falling back to the old latest-manifest-only behavior.
This allows a future separately provisioned CAS/witness signed-history
adapter to establish the missing owner-signed device authorization boundary.

The store also persists `signed_genesis_digest` in its local identity record
when it is **first created** in strict mode. A later attempt to reopen that
database with a different genesis or with strict mode disabled is refused
before changing the database. Older stores with no such identity field remain
readable in their previous explicitly experimental mode; they cannot be
silently upgraded to strict without a separate reviewed migration. This is
not a remote rollback-proof high-water mark.

The private brand from `verifyRecoveryHistoryPublicV2` now commits to
**both** canonical original `baseManifest` and canonical latest
`headManifest` bytes. Independent review reproduced a P2 where mutating
the otherwise branded `baseManifest` after verification previously retained
the trusted-public-proof brand. The regression failed before this binding
change and passes afterward; a forged owner genesis cannot inherit the
verified-brand status by altering public object fields.

## Versioned normal-app development bootstrap

`registerZk1ProtectedContentFromConfig` now accepts an explicit
**version 2** opt-in configuration in `development` or `test` only:

- the existing independently pinned CAS and live-witness HTTPS/mTLS settings;
- `signedHistory.genesisDigest` from the owner-controlled original genesis;
- a separately provisioned public `baseReceiptPath` (JSON with canonical
  base64url binary fields and an Ed25519 witness signature);
- `baseWitnessKeyId`, `baseWitnessPublicKeyPath` and a bounded
  `packageEnvelopes` list of activation revision + absolute file path.

Bootstrap validates the strict field shapes and genesis/scope binding **before
opening** the content SQLite store. A new
`createZk1SignedHistoryCasProofProvider` downloads full paginated CAS
history, verifies the exact genesis digest, independently pinned base
receipt, Ed25519 transition chain and all supplied recovery-package
activation envelopes, and returns **only the private-branded proof**. The
protected store separately checks the **fresh independently signed witness
head** and device-operation signature before any local ciphertext read/write.

Configuration **version 1** remains available solely as the old experimental
test/development fixture; it does not claim complete signed-history device
authorization. Production bootstrap of either version remains disabled.

## Verification evidence

The RED test `test/issue-65-protected-signed-history-authorization.test.js`
proved the prior store would accept an invented object advertising
`signedStateVerified: true` while no complete signed history was checked.
The GREEN test uses genuine Ed25519-signed genesis + device-enrollment
transitions with independent witness keys and a real SQLite protected
content store. It verifies refusal for forged/unbranded objects, a different
owner genesis, a previously valid but now stale historical head, and a missing
verifier provider; none release ciphertext or write a row. A correctly branded
signed history under the pinned genesis passes.

The original protected object fencing and CAS/witness ciphertext end-to-end
tests still pass without changing their explicitly experimental legacy mode.

An additional real two-server HTTPS/mTLS regression uses disposable CAS and
witness SQLite ledgers, versioned signed genesis + enrollment + revocation,
the strict CAS proof provider and an isolated protected SQLite store. It
confirms live encrypted PUT and GET by active signed devices, refusal of an
Ed25519-signed GET by the revoked device after the witnessed commit, and
continued access by the remaining active device. The test **does not**
claim distributed multi-host physical provider transfers, and its local
non-admission GET/PUT fixture is not a production authority.

Focused regression also verifies that invalid Ed25519 operation signatures
trigger **zero** full-history requests, and holding two legitimate signed
history verifications in flight causes a third pre-admission call to fail
closed without allocating a third verification worker.

## Remaining production blockers

The new v2 mode can be selected in the normal application's **development
opt-in only**, with separately provisioned public trust roots. An owner-facing
trust-root provisioning UI, durable independent operator infrastructure,
signed-high-water restore governance and migration authorization remain open.
Opt-in verification is not equivalent to independent infrastructure.
Even with a verified signed chain, the existing protected SQLite route is
not a production multi-host gate and does not atomically bind nonce/replay
consumption to independently proven physical provider GET/PUT/STOP. The
user-facing normal upload/restore/WebDAV/sync flows are not switched to
client-only ciphertext here. Do **not** merge, deploy, enable production
routes, migrate real content or close #65 based on this evidence.
