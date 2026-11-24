# #298 / #66: candidate native PREPARE → COMMIT boundary, **LAB ONLY**

**Scope:** exact local parent `265714ad851319566dfd9c044c17bc9f80c0baea`.
Do **not** import these helpers into `sync-client/rootark-sync-engine.js`.
They do not replace `ROOT_SESSION_CONTRACT`, supply native owner identity,
enable Files On-Demand, prove Windows 10 CFAPI or authorize a release.

## Authoritative contract reviewed (not merged into this PR)

The separate, unmerged branch
`cdx/issue66-root-session-contract-w2-20261109` defines the strict
`ROOT_SESSION_CONTRACT` in
`sync-client/rootark-sync-native-root-session-contract.js`. It specifies
`openRootFromTrustedParent`, `openChildDirectory`, `enumerateDirectory`,
`openContainedFile`, `readOpenedFile`, `createExclusiveFile`,
`renameNoReplace`, `removeEntry`, `syncOpenedFile`,
`syncDirectory`, `reacquireRoot`, `commitDurableRecovery`, and
`close`. Crucially, its activation gate always throws
`root_session_native_unavailable` or
`root_session_unverified_authority`; this independent test contract
**must not be promoted to an implementation or activation by copying an
export, object, Node FileHandle or JavaScript boolean**.

The distinct W3 Linux ext4 directory-fd experiments
(`cdx/issue66-posix-dirfd-w3-20261109`) demonstrate the benefits of
`openat2`, `O_NOFOLLOW`, `renameat2(RENAME_NOREPLACE)` and fd-bound
enumeration, **but** an opened POSIX parent fd can be renamed to a
different ancestry. The separate W26 Windows NTFS roadmap in commit
`dceeb9c3179bae28a4065583f754277ee31ba71c` at
`docs/roadmap/issue-66-pr300-native-custody-gates.md` explicitly
identifies **pre-first-native-pin B installed instead of original A**.
A self-acquired FileId of B does not attest original A. W26 post-pin
tests and signature-floor stubs do not satisfy independent operator
custody or product release. Neither branch is changed here.

## Smallest *potentially* integrable native interface

**Not callable by the application today.** This is a proposal for an
attested native backend, not a TypeScript/JavaScript interface:

| Phase | Native-only inputs | Invariants |
| --- | --- | --- |
| `ACQUIRE` | Independently authenticated owner-A root and parent lease, expected volume/mount/FileId, writer-isolation policy, authenticated cold floor | Reject self-enrolled root and any missing original-A proof before reading a mutable pathname |
| `PREPARE` | Live source file HANDLE/fd, its parent HANDLE/dirfd, held destination parent, exact single leaf, authenticated expected original identity and content proof | Pin physical source, directory/ancestors and immutable bytes; reject symlinks, reparse, mount changes, external aliases, concurrent writers; retain an unforgeable opaque transaction token |
| `COMMIT_LINK_NO_REPLACE` | Native token plus *one* exact destination leaf under the held parent | Atomic link **from the retained file object**, never `link(oldName, newName)`; existing destination fails without touching foreign contents |
| `COMMIT_MOVE_NO_REPLACE` | Native token and held parents | On NTFS `NtSetInformationFile(FileRenameInformation)` can operate on the source HANDLE. On Linux `renameat2` takes a **pathname** source: do not call it as though it were an FD-bound rename |
| `COMMIT_STAGE_RETAIN` | Native token and held trash directory | Linux can use a second original-FD link without deleting its source name; **this is staging without removal**, not a drop-in replacement for `stageExisting` |
| `COMMIT_DURABLE` | Journal/snapshot/marker native handles and independent monotonic CURRENT floor | Ordered fsync/FlushFileBuffers, directory flush semantics, cold-reopen/anti-rollback and no duplicate signed dispatch; crash ambiguity stays blocked |
| `REMOVE_EXACT` | Authenticated physical child identity and parent lease | Must never unlink a foreign inode by a swapped name; **not implemented in these labs** |

The **only implemented subset** is source-object identity retention,
link no-replace and (on Windows) rename no-replace in a single live
process. It deliberately cannot obtain original-A authority, enforce
same-principal writer isolation, safe deletion, root namespace ownership,
signed CURRENT-floor replay or crash recovery.

### Physical test-only implementation

The source files `w21-posix-fd-link-lab.cpp` and
`w21-win-handle-link-lab.cs` hold OS-native source and parent handles
from PREPARE until COMMIT, preserving the source's real inode/FileId when
a distinct same-UID/SID malicious second process swaps the old pathname
before COMMIT. Their tests check original/foreign identities and bytes,
no-replace collision and foreign preservation.

**Windows:** `PreparedOperation` validates source and parent
`FileIdInfo` at COMMIT. The lab exercises
`NtSetInformationFile(FileLinkInformation=11)` and
`NtSetInformationFile(FileRenameInformation=10)` with
`ReplaceIfExists=0`, `RootDirectory` set to an already-held
directory HANDLE and a single relative leaf. An occupied destination
must remain untouched after a collision. Rename moves the **opened
original file object**, not the current hostile source pathname.
All operations are on disposable NTFS fixtures.

**Linux:** `PreparedHeldLink` retains source `fd` and destination
`dirfd`, validating physical identity at COMMIT. It calls
`linkat(sourcefd,"",dirfd,name,AT_EMPTY_PATH)` when permitted or,
for an unprivileged test user, `linkat` via the kernel-owned
`/proc/self/fd/N` descriptor symlink. A second same-UID child process
swaps the source pathname. The original inode is linked; foreign content
is preserved; `EEXIST` prevents overwriting. A retained original-FD
hardlink into the held `.rootark-trash` demonstrates **non-destructive
staging**. `commitRenameByHeldFileUnsupported` explicitly returns
`ENOTSUP` to prevent claiming equivalence to unsafe name-based
`renameat2`.

### Reproduce with native Node22 per platform

Run explicitly, **never as a product release gate**:

```sh
node --test experiments/issue-67-pr298-unbound-name-evidence/w21-native-prepare-commit.lab.cjs
node --test experiments/issue-67-pr298-unbound-name-evidence/w21-second-process.cjs
```

The opt-in runner requires NTFS on Windows or `TMPDIR` on real ext4
for Linux, and checks Node **22**. It compiles the isolated native
programs using known system compiler paths into disposable OS-scratch
directories, tests them, then removes the compiled binaries. The
platform-irrelevant runner case is deliberately skipped. The
second-process suite runs three legitimate POSITIVE cases and three
real physical **EXPECTED SECURITY RED** races against the existing
Node product implementation. `PASS` on these attack tests means
the vulnerability was reproducible; it is **not security GREEN**.

### Required remaining gates (not bypassable)

- External signed owner-A root and parent fingerprints, image provenance,
  and native lease custody **before the first path lookup**; cold
  reacquisition must reject self-pinned attacker B.
- POSIX ancestry escape and bind-mount A→B→A under a same-UID writer;
  Windows owner ACL/mapping/share-mode and original physical FileId
  semantics under sustained hostile loads.
- A native, identity-safe **destructive** stage/rename and cleanup on
  both OSes, covering crash-after-PREPARE, post-COMMIT uncertainty,
  progress alias nlink2, and exact expected file contents.
- The other RootSession operations and full ledger/history/move/delete
  call graph: no fallback to JS `lstat`/`rename`/`unlink`.
- Durable marker, flush and independent CURRENT floor, 16,385+ exact
  Unicode entries, independent SOURCE reviews, hosted CodeQL and
  exact-SHA release gates.

**Status:** bounded primitive SOURCE candidate / full #298 and #300
PRODUCT, MERGE and RELEASE **NO-GO**. No FOD positive, Windows 10
CFAPI, off-host custodian or physical power-cut evidence is claimed.
