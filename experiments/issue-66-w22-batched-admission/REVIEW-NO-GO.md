# Issue #66 W22 — journal batch admission experiment (SOURCE ONLY)

Base: published #300 `407497b75e1a0316242371f3f33641f042b69d79`.

**Decision: NO-GO for production exclusion eviction, DELETE, reconciliation, and cutover.**

The working, bounded primitive `SyncJournal.batchObserveAdmission(entries)`
detaches validated `{operationId,digest}` pairs before awaiting its queued
transaction, rejects duplicate/conflicting IDs and capacity overflow, and
persists all of its observations in **one** existing fsync-backed JSON journal
transaction. The probe in `preflight.js` copies an entire LIST before awaiting,
verifies exact per-object Ed25519 signatures against independently supplied
device pins and revocation, checks the configured key epoch and expiry, checks
AEAD and static portable physical collisions, and only then commits its pins.
Already-pinned exact digests can pass historical expiry but still require a
current nonrevoked signer. A later invalid member aborts the whole LIST with no
new observation. No production sync path invokes the probe; it has no
filesystem mutation API.

This demonstrates a bounded transaction for authorization **evidence**. It is
**not** a replacement for #300's eviction-ledger PREPARE/replay protocol:

1. **P1 — missing physical transaction identity.** A digest-only journal pin
   proves that signed bytes were checked; it cannot prove which NTFS/ext4 inode
   moved into `.rootark-trash`, what its immutable source/escrow identity is,
   or whether an eviction completed if the process crashes before the full
   snapshot checkpoint. Existing required-v2 recovery needs the per-object
   PREPARE's object/file identity, path, content hash, and exact remote digest.
   Dropping those records allows a cold reopen to misclassify missing local
   bytes as a user deletion. No code in this experiment stages a file or
   disables/rewrites `evictionLedgerRequired`.
2. **P1 — filesystem ABA / pathname swap.** Static `contained`, `readdir`,
   and `lstat` checks cannot pin parent identities across an asynchronous
   `rename`/`unlink`. A competing writer can swap an ordinary directory away,
   put a replacement at its pathname during a stage, and restore the original
   afterward. A parent symlink introduced at cleanup can redirect a deletion
   outside the root. Native handle-relative leases on *every* ancestor and
   pinned leaf, no-reparse semantics, writer exclusions, and no-clobber rename
   must be proven on real NTFS/ext4 before connecting a batch to mutation.
3. **P1 — crash-compatible migration and epochs.** A journal-integrated
   eviction PREPARE needs an explicit old-client version fence and a durable
   snapshot/journal epoch link before any mutation; every crash boundary
   (journal-first, snapshot-required, stage, deletion, checkpoint, cleanup)
   must replay without losing bytes. The #300 zero-genesis, missing-ledger,
   retained-head and >16,384-trash invariants must remain intact. Treating
   historical `observed[]` entries as eviction commits is invalid.
4. **P2 — trust and LIST freshness.** The inert probe accepts a fixed,
   independently supplied current device-pin/revocation view. Production must
   bind that view to a trusted, monotonic authorization epoch across preflight
   and fsync, and prove completeness of a fetched LIST if external changes or
   pagination may occur. Per-record Ed25519 signatures prove each record's
   authenticity, but not completeness of the inventory. A physical alias may
   appear after static preflight; the inert probe rejects path collisions at
   its observation time and makes **no** claim of atomic filesystem custody.

Intentional liveness tradeoff: the probe rejects a LIST over 640 records and
conflicting or same-casefold paths, even if later ordered operations could be
safe. If the last member fails or EIO precedes journal rename, earlier fresh
proofs are **not pinned**; later expiry can require reauthorization. This is
preferable to granting authorization before the entire batch is validated.
If directory fsync fails *after* rename, the journal reports an indeterminate
ACK and retains the committed state in memory; cold reopen determines the
durable observation. Neither case authorizes external physical writes.

Tests are in `test/issue-66-w22-batch-observe-admission.test.js` and
`test/issue-66-w22-sidecarfree-preflight.test.js`. They cover a signed DELETE
without executing it, a late invalid Ed25519 LIST member, current revocation,
epoch, expiry, id collisions, physical case collisions, simulated rename EIO,
directory fsync EIO, process exit after commit before staging, mutable argument
TOCTOU, cold reopen, and 160/640 Ed25519+AEAD performance. They cannot prove
concurrent native directory-swap resistance or power-loss durability and are
**not** an operational safety gate. Additional independent exact-SHA source
review and native transaction tests are required before any integration.
