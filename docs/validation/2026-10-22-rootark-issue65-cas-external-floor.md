# Issue #65 — CAS terminal signed-continuity floor (2026-10-22)

## Implementation scope

The existing `Zk1CasTerminalAnchor` remains a **single-host** signed
append-only journal. The owner/operator may now supply an **independently
retained**, externally provisioned `{sequence,lastHash}` head as
`trustedMinimumHead` to the journal or `trustedAnchorMinimumHead` to
`Zk1DurableCasStatusLedger`. The fields are read only from own data
descriptors and copied into private immutable state. An on-disk journal
behind that sequence, or a different signed branch at that exact sequence,
is rejected both at startup and on all read-side access.

`headCheckpoint()` returns the SHA-256 hash of the *signed canonical record
line*, not an unsigned database revision or untrusted caller string. It is a
**candidate** for an outside owner/witness to retain. Reading it back from the
same CAS disk and supplying it to the constructor does **not** create an
independent trust boundary. The independent floor is optional for the current
reference integration; absence must never be described as rollback proof.

Read-side `get()` and `hasScope()` now reread and authenticate the entire
bounded journal bytes via an `O_NOFOLLOW` fixed file descriptor with bigint
path/FD identity checked before and after reading, rather than trusting file
size and `mtimeMs`, which the filesystem owner can restore after changing
bytes. An unchanged SHA-256 **content digest** reuses an immutable/private
previously validated Ed25519 snapshot; any changed bytes trigger full
canonical parsing and signature verification. This avoids per-GET synchronous
Ed25519 scans over thousands of valid records while retaining the read-side
tampering checks. Append verifies the same inode, byte length and regular-file
identity under the private journal append lock before writing and after fsync;
it refuses a swapped same-content target rather than signing success against
the wrong file. The ledger checks the optionally pinned journal before opening
its SQLite database in write mode, and again when creating the operational
anchor handle. An externally pinned nonempty head prevents both empty CAS
SQLite and empty journal bootstrap *before creating either file*.

## Adversarial validation

The focused tests cover a legitimately signed journal rolled back to an old
prefix, a *different legitimately signed fork* at the same sequence and byte
length, mutable caller floor, and on-disk signature corruption hidden behind
an identical file size and injected stale timestamp. The CAS ledger test
also verifies that a pinned floor prevents reopening a rolled-back terminal
journal before SQLite write-mode initialization. Further tests exercise
mid-read signed-prefix swaps, replacement of the inode after verified reload
but before append, caller mutation of the input floor, an attempted fresh
bootstrap with an existing external floor, and the fact that 25 unchanged
reads do not redo an entire Ed25519 signature scan whereas changed bytes do.
The tests use only private disposable directories, synthetic Ed25519 keys
and no external credentials.

## Windows hosted CI follow-up

The earlier PR SHA `1028c8d` passed Ubuntu/PG18/CodeQL but its hosted Windows
Node 22 canonical npm test failed (1934 PASS/16 FAIL/145 SKIP), including
valid offline backup fixtures under `UNSAFE_FIXTURE`. A fully owned Windows
`%TEMP%` junction reproduces one positive signed fixture incorrectly refused.
`zk1DisposableBackupPreRestore` now allows the **OS-supplied temporary-root
alias only** when its real path is stable, while pinning the actual private
fixture under the canonical temporary parent. The private fixture and child
directories still reject symbolic links/junctions; the alias cannot change
during inspection. The three adversarial directory-swap test hooks use their
canonical fixture path, so they still execute when `%TEMP%` is aliased.
The local Windows Node 22.23.0 synthetic junction suite passed 17/17;
independent GitHub CI for the new exact SHA must still be verified separately.

## Limits

- No independent remotely operated floor store, quorum, mTLS signing service,
  or cross-host CAS compare-and-swap was provisioned by this change.
- A compromised host retaining both the journal and the only copy of the
  owner floor can still rewind both. The caller must provision, protect,
  advance and persist the floor **outside** the CAS operator's authority.
- SHA-256 streaming-equivalent over the bounded 64 MiB journal is still an
  O(bytes) synchronous read/hash, not a scalable independently anchored log.
  Cryptographically signed contents are revalidated whenever bytes change.
- No normal protected-content access, backup restore, deployment, or merge is
  authorized or claimed by this patch.
