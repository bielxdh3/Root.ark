# W22 follow-up — strict signed remoteOnly CREATE/UPDATE batch probe

Baseline: local W22 review commit `a387dfde1e9f41c4951dd5c6c4ba95afed404f5c`,
itself based on published #300 `407497b75e1a0316242371f3f33641f042b69d79`.

**Decision: experimental SOURCE PASS for the isolated metadata-only path; NO-GO
for any production integration.** `SyncEngine._pullRemote` and its existing
per-operation behavior are unchanged. The new module
`remote-only-full-source.js` is not referenced by the production engine or
CLI, and the new journal `batchMarkSeenRemoteOnly` method is not called by
production code. No eviction stages, source moves, DELETEs, reconciliation,
remote pushes, sidecars, or eviction-ledger transitions are performed by this
probe. No PR push, merge, deployment, or cutover is authorized by these tests.

## Accepted static subset for the inert experiment

The probe opens the existing source engine under its normal exclusive
cross-process root lock, fetches an unpaginated `adapter.list()`, and
canonical-copies every record before asynchronous checks. The entire list must
have at most 640 members and contain only independently Ed25519-verified,
AEAD-decryptable signed CREATE or UPDATE records with fresh key epoch, a
current unrevoked signer, unique operation IDs/object IDs and portable
casefold-distinct paths. Operations must target an explicitly **excluded**
path, with no sourcePath, tombstone, DELETE, MOVE, directory, selected hydration
or local physical mutation. A CREATE is allowed if no previous remote-only
object exists, or if it exactly matches a previously pinned CREATE being
replayed after a crash. An UPDATE requires the same existing excluded
remote-only objectId/fileId/path. The listed objects must include every
existing remote-only identity; any evicted, deleted or directory marker is
ineligible.

Before any journal/snapshot mutation, the snapshot must have no tracked
files, pins, pending evictions or required eviction ledger; the journal must
have no pending outbox or atomic DELETE+MOVE group. An independent external
policy provider must return the owner username, pinned device keys, key epoch
and a nondecreasing authorization-policy epoch at least as high as an
independently pinned minimum. That policy is checked before verification,
immediately before journal observation, immediately before snapshot, and
before batch acknowledgement. An epoch rollback, revocation or key mismatch
fails closed. The owner's pinned key set is detached before the first await.

A strict physical **negative** canary checks that the entire sync root
contains only its exact journal/index files and the empty exclusive root lock.
Any local data file, tracked or untracked directory, symlink/junction, staged
trash, old ledger, case alias, or unexpected root entry blocks the probe.
Check again after all signatures and before snapshot. All these are ordinary
path-based checks; they do **not** become a native handle lease.

After full LIST verification the probe uses the existing
`batchObserveAdmission` to pin all eligible SHA-256 envelope digests in one
durable journal transaction, saves one snapshot containing excluded
`remoteOnly` markers, and uses a new bounded `batchMarkSeenRemoteOnly` to
atomically promote exactly those already observed digests in one journal
transaction. The latter refuses duplicate IDs, unobserved or conflicting
digests, locally pending IDs and atomic signed WebDAV group members. This is
three pathname-based fsync/rename transactions for both 160 and 640 records
(the prior per-object loop required far more journal commits). No physical
cache data is written or removed.

If the final signature is invalid, no journal observation or snapshot marker
is added. If journal EIO occurs before its rename, no pin is added. If an EIO
or hard process exit happens after observations but before the snapshot, a
cold reopened client retains observations and can retry the **exact signed
bytes** (including after expiry, subject to current revocation checks). If
the snapshot persists before acknowledgement, the same idempotent CREATE
recovery completes the batch markSeen after restart. A hard process crash
leaves the engine's exclusive lock intact and requires explicit recovery; the
disposable tests remove the empty lock only after observing the child exit.

## Why production remains NO-GO

1. **P1: pathname ABA after physical preflight.** Root/ancestor `lstat` and
   `readdir` cannot pin a directory's identity across the subsequent await,
   `fsp.open`, `rename` and cleanup calls. The current sync engine's
   `durableJson` uses a path-based temporary `fsp.open`, then `rename`, and
   on error `fsp.rm(temporary)`. The journal's `durableWrite` likewise uses
   a pathname temp `open`, `rename` and `unlink` on failure. An external
   writer swapping a root or ancestor to a directory link after the last
   static check can redirect **metadata** writes or cleanup outside the
   authorized root. Restricting physical cache operations to none does not
   cure this; there is no native rooted handle with no-reparse, ancestor
   custody and no-clobber semantics in the existing filesystem API. The
   `W20` ext4 transient ABA and cleanup-to-external-canary failures therefore
   remain relevant even to a metadata-only optimization.
2. **P1/P2: signed LIST completeness and current policy custody.** Ed25519
   signatures prove individual envelope authenticity, not that the server
   supplied the complete current inventory, nor that a concurrently changed
   owner policy cannot roll back between asynchronous checks. The probe
   rejects pagination and omissions of already-known remoteOnly objects,
   but the server's LIST has no independently signed complete-set/epoch
   witness. A production optimizer needs an externally monotonic owner
   authorization floor, synchronized revocation policy, and complete signed
   inventory checkpoint before allowing any new trust-dependent fast path.
3. **P2: unsafe fallback under invalid later members.** The existing
   per-operation path is retained; it may have advanced prior records before
   encountering a later invalid Ed25519 envelope. The test guarantees
   all-or-nothing **only in the inert probe**. Before integration, the
   production decision needs an explicit fail-closed or fallback policy
   that cannot silently reintroduce partial observations or mutate local
   cache through mixed MOVE/DELETE records.

## Evidence and next gate

Native Win22/NTFS and WSL22/ext4 tests cover complete real Signed LIST with
Ed25519, pinned device keys, AEAD, epoch/revocation, 160/640 throughputs,
empty-root/physical-file/dir/case-alias/staged-trash/symlink-junction external
canaries, EIO before snapshot and batch markSeen, an inserted canary between
observed and snapshot, hard process exit after observation and after snapshot,
expiry after durable pin, late forged signature, CREATE replay, UPDATE, and
MOVE/DELETE/tombstone rejection. The tests only claim their observed scope;
real-time adversarial ABA and power-loss durability need independent native
peer reproduction on the exact final commit. Existing #300 ledger-required,
zero-head, and >16,384-trash proofs remain untouched.

The next implementation must first establish descriptor-relative durable
root-scoped metadata writes and cleanup (or a proven external-writer
exclusion mechanism), signed complete-inventory/epoch custody and a strict
production feature gate. Until then this experiment remains inert.

## Independent P2 follow-up — negative tests, not a production clearance

The independent review of the integrated experimental chain reproduced two
counterexamples to the *inert probe's own* strict preflight claims. A hidden
regular file nested under the allowed `.rootark-sync.lock` directory passed
the original root scan. A fresh signed operation could also expire during
an awaited `beforeCommit` policy check or an earlier queued journal commit,
yet acquire a new durable admission receipt. Neither counterexample was a
production call: the experiment is deliberately disconnected.

The follow-up adds native-file negative tests and rejects a lock directory
containing any child inode, reading at most one entry. It checks expiry both
after full signed-LIST validation and *inside the queued journal mutation*,
after the final awaited policy gate and before the durable write begins.
The crash fixture now runs a static `.cjs` child instead of interpolating
runtime values into executable `node -e` source. The tests retain their
original Ed25519, revocation, EIO and no-mutation assertions.

**Remaining limit:** validation at the start of `durableWrite` does not prove
the filesystem persisted a directory entry before the signed expiry instant
if I/O is stalled, nor is local `Date.now()` an externally trusted monotonic
authority. A hostile ancestor swap may still redirect pathname-based writes
after preflight. No production `_pullRemote` hook, automatic recovery, NTFS
power-cut guarantee, owner-signed completeness witness or cutover is granted.

An independent follow-up also reproduced a revocation gap at the **final
acknowledgement**: a policy could change while `batchMarkSeenRemoteOnly()`
waited behind another journal transaction. The previous check happened before
enqueue, allowing a revoked signer to acquire a newly acknowledged `seen`
record after revocation. The inert batch ACK now accepts an internal queued
`beforePersist` callback and repeats the exact pinned epoch/revocation/root
check after older transactions finish. A signed end-to-end negative test
reproduces the old ACK race RED and verifies that the new code leaves the
already-durable observation unacknowledged after revocation. This is a
last-before-write policy check, not a trusted distributed revocation clock or
a promise of NTFS metadata durability after power loss.

The next independent review identified a distinct **zero-new-observation
replay** bug in the exported inert preflight API: when every Ed25519 record
was already observed or admitted, `batchObserveAdmission([])` previously
returned before invoking its mandatory `beforeCommit` owner-policy callback.
Tests reproduced the omitted gate with genuine signed CREATE and DELETE
records, an observed journal digest and late revocation; already-admitted
CREATE and a queued journal transaction were also checked. The zero-length
batch now runs `beforePersist` in the same ordered journal queue, without
creating an unnecessary journal rename, preserving every prior receipt and
rejecting revocation. This fixes the **API contract**, not an observed
production bypass: the wrapper separately rechecks policy before snapshot
and final ACK, and remains disconnected from production.
