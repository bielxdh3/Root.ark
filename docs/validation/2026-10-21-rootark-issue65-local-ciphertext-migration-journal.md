# Root.ark #65 — disposable offline ciphertext journal

**Status:** experimental, fixture-only; **not authorized for production migration**. The independent S3/Google Drive inventory preflight remains read-only, `canMigrate: false`. No server route, production adapter, SQL, WebDAV, cloud account, or real user file is wired to this module.

`src/services/zk1LocalFixtureMigrationJournal.js` exports `runLocalFixtureCiphertextMigration`, `verifyLocalFixtureCiphertextMigration`, and `rollbackLocalFixtureCiphertextMigration`. Each takes the same explicit fixture plan. There is no implicit execution or provider discovery. Every report carries `canMigrate:false` and `rollbackScope:"local-fixture-only"` even after the local copy is verified.

The fixture directory must be an immediate child of `os.tmpdir()` whose name starts with `rootark-zk-local-fixture-`, have the exact marker `.rootark-disposable-fixture` containing `rootark-zk-local-fixture-v1\n`, and pre-existing `source/`, `target/`, `journal/`, `references/{versions,backups,trash}/` directories. The caller must create this **freshly with synthetic ciphertext**. A path and marker cannot prove that a malicious or careless caller did not copy private data there. This code assumes a trusted single-process, non-concurrent disposable fixture with ordinary filesystem semantics. It rejects symlinks on the fixture root and inspected entries, linked source/reference files, traversal or unsafe IDs, payloads over 16 MiB, reused targets, and unsupported or incomplete reference sets.

Plans name one synthetic object (`source/<objectId>.ct`, `target/<objectId>.ct`) and one operation ID. A lowercase hex SHA-256 commitment covers the source bytes. The inventory requires **nonempty** synthetic versions, backup and trash reference lists with per-entry SHA-256 commitments and presence checks, all independently reopened before any write, before commit and before rollback. `sourceProvenance` must be `{role:"source",provider:"fixture-source",identity:<opaque-id>}`, and `targetProvenance` must be `{role:"target",provider:"fixture-target",identity:<distinct-opaque-id>}`. These are *caller-asserted fixture labels*, not independently authenticated cloud principals or owner-signed authorization. Mismatched plans and duplicated names fail closed.

The local transaction deliberately copies already-encrypted bytes and **does not** decrypt, re-encrypt, claim AEAD authentication, advance the signed ZK envelope/version registry or migrate current legacy server-readable keys. The source and all references stay untouched. The committed destination cannot be accepted as a runtime ZK object.

## Journal, interruption and rollback

1. After checking inventory and absence of the destination and stage, atomically publish an exclusive `planned` journal (synced temporary file + `link` without overwrite). Journal records bind plan, phase and SHA-256 checksums; checksums detect accidental/malformed changes but are **not a signature or adversary-proof authority**.
2. Write and `fsync` the destination staging file, exclusively. The synced file is hard-linked into an absent target, so publication is atomic and cannot replace a pre-existing target. Unlink the stage after publication. Verify the destination by reopening and hashing it separately from the write buffer, while revalidating source and all inventory references.
3. Atomically replace the journal (`fsync` temporary + same-directory rename) with `committed`. A replay of the same plan verifies disk state and succeeds idempotently. A changed digest, operation scope, reference, provider identity, stage or destination fails closed. A `planned` journal can resume after interruption before or after destination publication; partial/tampered artifacts are retained for manual inspection, not silently repaired.
4. Rollback revalidates the source, references, destination and any stage **before** publishing `rollback-pending`. It unlinks only the verified synthetic target and stage, then persists `rolled-back`. Interrupted rollback can resume. A rolled-back operation ID can never silently remigrate. The journal and source are retained; no original byte is overwritten, deleted or re-encrypted. If the original is missing or altered, rollback refuses and retains the destination, avoiding deletion of the sole remaining known copy.

Files are checked with no-follow descriptors where supported, inode/size/link-count identity, SHA-256 and static directory fences. Same-directory `fsync` is used on POSIX for directory entries; Node.js on Windows has no portable directory-entry `fsync`, so **sudden power loss is not guaranteed recoverable on Windows**. Atomic link/rename and file `fsync` are verified only within the local fixture filesystem; cross-filesystem moves, concurrent external writers, NTFS reparse race attacks, disk corruption and adversaries capable of rewriting a journal plus its checksum remain outside the guarantee.

The targeted Node tests exercise synthetic reference requirements, tamper/stale/replay rejection, path/symlink/hardlink protection, exclusive destination, no loss of the initial source, injected interruptions at every declared checkpoint, and actual child-process exit during publication and rollback. Tests use temporary fixtures and never invoke live storage.

The fixture inventory now requires an **exact closed-world match** between
the declared synthetic `versions`, `backups` and `trash` IDs and the
filesystem directory entries. A previously unlisted reference file or other
unexpected entry blocks initial copy, post-commit verification and rollback
rather than quietly declaring a partial inventory complete. The regression
`undeclared ciphertext versions, backups or trash cannot be silently omitted`
was RED on the previous journal implementation (14 pass, 1 fail), then
GREEN with the exact-directory check (15 pass, 0 fail). This is an ordinary
local directory enumeration, **not** an authenticated remote provider
inventory or a defense against a concurrent privileged filesystem actor;
it does not make `canMigrate` true.

An additional process-crash boundary is now covered: initial exclusive
publication uses `link(temp, journal)`, which briefly gives the same journal
inode **two hard links** before the temporary name is unlinked. Real
`process.exit(71)` immediately after the link formerly left a valid planned
journal that every replay rejected because its link count was 2. The replay
path now reconciles only a `planned` journal matching the exact requested
plan, canonical journal checksum, one expected randomly named same-directory
temporary hard link (24 hexadecimal nonce), identical inode and identical
content. It removes only that verified temporary name, flushes the directory
where supported, and requires the original journal to remain on the same
inode with exactly one link before continuing. An unknown journal hard link
or mismatching artifact remains a hard refusal and is not deleted.
RED: 16 PASS / 1 FAIL on actual child exit at this micro-window;
GREEN: **17/17 PASS, 0 FAIL** with the exact recovery and hostile-hardlink
regressions. This is still limited to trusted, non-concurrent disposable
fixtures and does not guarantee Windows power-loss durability.

Follow-up: two independent process deaths can leave a **different one-link
temporary orphan** from a failed pre-link publication alongside the valid
two-link journal/temp pair from a later post-link crash. The retry now
selects the one temporary filename with the expected pattern **and matching
journal inode**, while leaving unrelated orphan files untouched. The
repeated-crash regression was RED (17 pass, 1 fail) before this correction.
GREEN is **18/18 PASS** on Windows and on WSL Node 22.22.1, including a
verified surviving unrelated orphan and the original synthetic source.
The inode/name check only identifies a *structurally matching* link: it is
**not an origin proof** against a privileged or malicious filesystem writer
who fabricates an exact matching-pattern hardlink. Such an actor is explicitly
outside this trusted, non-concurrent fixture boundary, and a release-quality
journal would need an independently provisioned authority and stronger
mutation isolation. Do not use this recovery helper on real user data.

**Production blockers:** owner-authorized and client-decrypt-verified migration, independently trusted source and destination provider roles/freshness, signed object/manifest revisions, authoritative versions/backup/trash/links/derived/sync/WebDAV inventory, cross-provider transactional fencing/reconciliation, retention/erasure policy and validated real-provider recovery. Until those exist, every outcome here means **LOCAL fixture experiment only**, never `canMigrate:true`, release readiness or a ZK cutover.
