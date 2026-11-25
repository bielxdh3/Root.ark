# Issue #66: native RootSession contract (not integrated)

**Status: test-only contract, SOURCE/OPERATIONAL NO-GO for recovery.** The
module `sync-client/rootark-sync-native-root-session-contract.js` has no
runtime callers and ships no native addon. Its gate always rejects activation,
including `true` and a caller-provided object. It does not certify that the
active `SyncEngine` has root custody.

## Threat and authority boundary

In `rootark-sync-engine.js`, a held POSIX descriptor of `.rootark-trash`
(`618–622`) is not the descriptor used by `fsp.opendir(trash)` (`623`).
`readContainedFile` (`280–326`), the physical recovery scan (`2722–2803`),
the ledger (`572–853`), snapshot (`500–524`, `1421–1424`), and staging
(`2530–2539`, `3267–3309`) still reopen paths. A bind-mount A→B→A can
present clean bytes for the scan while the required-v2 checkpoint belongs to
the dirty original A. Windows same-principal swaps and spoofed timestamps
cannot be settled by more `lstat` or JS `FileHandle` comparisons. Node 22
does not expose the necessary cross-platform descriptor-relative operations
through `node:fs`.

An eventual backend needs a **separately protected parent/root authority**
at acquisition and cold reopen, a trusted volume/mount and ancestor policy,
and a way to exclude or snapshot concurrent same-principal writers throughout
proof and durable commit. A JavaScript field named `native`, a `FileHandle`, a
local digest or a returned `stat` object is not that authority. Merely loading
a `.node` file by pathname is not attestation of its mapped bytes or runtime
dependencies. Backend binary provenance and installation ACLs require their
own independent review.

## Proposed native API, version 1

All arguments representing directories or files below are **opaque native
session handles**, minted and validated inside the native service. Names are
single exact child names, not caller-joined absolute paths. These are required
operations, not implemented JavaScript functions:

| Operation | Required contract |
| --- | --- |
| `openRootFromTrustedParent(policy)` | Acquire protected parent/root, pin all ancestors, owner/ACL and volume/mount identity, reject reparse or foreign mount |
| `openChildDirectory(parent, name)` | Resolve only beneath pinned parent; no symlink, reparse, junction or mount crossing |
| `enumerateDirectory(dir)` | Stream entries from **that exact open dir**; no separate pathname enumeration |
| `openContainedFile(parent, name)` | Open regular file from pinned parent; reject hardlink alias and identity mismatch |
| `readOpenedFile(file)` | Read/hash from the same protected file object; block concurrent mutation or require protected snapshot |
| `createExclusiveFile(parent, name)` | Native exclusive creation; never overwrite an existing or dangling alias |
| `renameNoReplace(fromParent, name, toParent, name)` | Native no-replace move between pinned parents, preserving ownership/identity |
| `removeEntry(parent, name)` | Delete only the verified object relative to held parent, without foreign cleanup |
| `syncOpenedFile(file)` | Durably flush bytes and return an explicit error on uncertainty |
| `syncDirectory(dir)` | Durably flush namespace transitions with platform-specific evidence |
| `reacquireRoot(policy)` | Cold reopen from independently trusted parent and anti-rollback anchor; reject ABA |
| `commitDurableRecovery(session, state)` | Atomically order marker, PREPARE/COMMIT, snapshot, namespace flushes and independently verifiable commit |
| `close(session)` | Release native handles without reporting success for unresolved operations |

On Linux, an implementation candidate is `openat2` with
`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV`, handle-bound
enumeration (`fdopendir`/`readdir`), `renameat2` with `RENAME_NOREPLACE`,
`unlinkat` and `fsync` on held directory descriptors. These flags alone do
not isolate a concurrent writer with permission to alter already opened data.
On Windows, candidates include `NtCreateFile` with a trusted
`OBJECT_ATTRIBUTES.RootDirectory`, `FileIdInfo`/volume and reparse checks,
handle-relative enumeration and no-replace rename, with reviewed share modes,
ACLs (including `DELETE` and child-delete authority), flushes and cold-reopen
semantics. The existence of a Win32 handle alone proves neither source-byte
integrity nor durable namespace state.

The smallest safe integration migrates **all** recovery reads and mutations
to a single native session: genesis enumeration and marker read/promotion,
the complete tracked-file scan, ledger/snapshot/journal I/O, stage and
restore, PREPARE/COMMIT, rollback and durable checkpoint. It must leave
`evictionLedgerRequired=true` whenever any proof, rollback or flush is
uncertain and must never authorize a signed remote DELETE from such recovery.
Partial integration that still reopens a path reintroduces the ABA window.

## Required behavior and verification

- **Legitimate large trash:** stream all **16,385 or more** existing
  `.rootark-trash` entries without silently truncating at 16,384; detect
  staged genesis case aliases anywhere in the stream. Other documented ledger
  and tracked-directory bounds remain unchanged.
- **Unicode:** preserve exact physical name identity, including composed and
  decomposed forms; reject ambiguous casefold/normalization aliases rather
  than silently rewriting a tracked name. Windows UTF-16 and POSIX raw name
  representations must be reconciled deliberately in the native layer.
- **Adversarial RED:** physical POSIX A→B→A mount replacement at each native
  enumerator/open/read/stage/promote/journal/commit/cold-reopen boundary;
  Windows NTFS same-principal rename/reparse and timestamp spoof with a
  separately protected root. Verify zero remote signed DELETE, no foreign
  modification, retained required marker and crash-safe rollback.
- **Durability RED:** native file/directory flush failures, rename collisions,
  process crashes before/after genesis, PREPARE, staging, COMMIT and final
  snapshot; cold reopen must never treat a missing/rolled-back chain as clean.

The seven focused Node unit tests only demonstrate the **unavailable gate**
and this immutable list of requirements. They do not simulate a native handle,
prove filesystem security or replace the physical hostile tests. The
standalone `rootark-sync-windows-cfapi-acl-preflight.cpp` is a useful
`FileIdInfo`/ACL probe but explicitly does not pin ancestors; no integrated
RootSession backend was found at this checkpoint.
