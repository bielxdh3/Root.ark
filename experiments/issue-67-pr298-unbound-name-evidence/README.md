# PR #298 / Issue #67 — W21 unbound-pathname publication evidence

**Source**: published PR #298 `ce393b75b676119d7ac6f2e74e17a43421bd6cf9`.
**Verdict**: **SOURCE NO-GO** for same-SID/UID concurrent namespace writers.
This is a bounded, synthetic **RED reproduction**, not a production patch,
security regression GREEN, or authority for merge, release or deployment.

Run `node --test experiments/issue-67-pr298-unbound-name-evidence/w21-races.cjs`
from the repository root using **Node 22**. On WSL use `TMPDIR` on a real
ext4 volume (e.g. `TMPDIR=/home/<linux-user>`), not `/tmp` if it is tmpfs.
Dependencies must already be resolved (e.g. via an existing `NODE_PATH`);
this lab does not install anything. On Windows the synthetic temporary root
must be on **NTFS**. The experiment intentionally has a name without
`.test.js`, so the canonical Node test discovery does not run it.

### What the 5 explicit test cases prove

1. **Positive**: `createDurableRestoreProgress` writes/fsyncs its private
   original temporary and publishes the same inode by hard link with nlink=2.
2. **Security RED**: immediately before its actual `fsp.link(tmp, final)`
   syscall, a same-process test hook renames the fsynced temporary to a
   retained alias and creates an unrelated synthetic inode under `tmp`.
   The original syscall then publishes **the foreign inode** as `final`,
   while the originally fsynced descriptor is still held. The test
   checks physical `dev/ino` and both byte streams.
3. **Security RED**: immediately before `stageExisting`'s actual
   `fsp.rename(target, trash)`, the original source is retained by a second
   name and a synthetic foreign inode takes `target`. The actual rename
   stages the **foreign inode**, not the selected original. Held descriptors
   and physical inode identities prove it.
4. **Positive**: a real Ed25519-authorized historical restore materializes
   the authenticated bytes and pushes its signed update successfully.
5. **Security RED, with a preserved safety gate**: immediately before
   `_apply`'s historical `fsp.link(tmp, target)`, the source temp is
   swapped for a synthetic foreign inode. The *real* hardlink syscall puts
   foreign bytes at the local target. The existing `_pushPending` local
   SHA256/authorization check then denies remote dispatch with
   `restore_local_materialization_missing`; **remote pushes remain zero**.
   This is local inode publication damage, **not** proof of remote compromise.

Only disposable synthetic files are involved. The original and foreign
descriptors remain open through the identity/bytes assertions and are closed
before cleanup. These are real NTFS/ext4 `link`/`rename` syscalls *after*
a deterministic interception of JavaScript's `fs.promises` entry point.
They do **not** simulate or prove independent second-user process/SID/UID
concurrency, cross-root ancestor replacement, cold start, or atomic cleanup.
Tests showing `PASS` mean **RED was successfully reproduced**, not that
production has been fixed.

### Exact source trust boundaries

- `sync-client/rootark-sync-engine.js` `createDurableRestoreProgress()`:
  `fs.promises.link(temporary, filePath)` receives a mutable source *after*
  the original FileHandle was closed. The destination is no-replace, but the
  source's identity is not bound to that FileHandle.
- `SyncEngine.stageExisting()`: the source `target` is checked by path,
  then `fs.promises.rename(target, trashTarget)` resolves the source name
  anew. Retaining an FD elsewhere does not make this rename conditional on
  its file identity.
- `SyncEngine._apply()`: `fs.promises.link(temporary, target)` and the
  subsequent `fs.promises.rm(temporary, { force: true })` also resolve a
  mutable name. The signed outbound materialization guard denies a wrong
  local payload before remote dispatch, but cannot undo a local publication.

### Why no apparently simple patch is acceptable

An extra `lstat`, `fstat`, `realpath` or content hash immediately before
or after any of these mutating syscalls does **not** provide atomic
identity-scoped publication or removal. `O_NOFOLLOW` is limited to opening
the final source component, not conditional hardlink/rename. Replacing
no-clobber hardlink publication with `open(final, 'wx')` and writing in
place destroys the invariant that a crash before initial fsync cannot leave
an incomplete final progress journal. A false-positive test rewrite or
blanket rejection of legal restores is not an acceptable fix.

The existing native experiments
`scripts/issue-67-native-contained-open.cpp` and
`scripts/issue-67-native-contained-read-{win,posix}.cpp` are explicitly
**read-only LAB** code. They do not implement a reviewed, deployable
cross-platform identity-bound writer. A safe solution needs retained
root/parent capabilities with external identity/authority validation,
descriptor-bound publication, no-replace destination, durable directory
checkpoint, and safe handling of interrupted operations. On POSIX,
`linkat(AT_EMPTY_PATH)` can link a held inode, but source-name removal
still needs a separate integrity/custody design. On Windows,
handle-based link/rename APIs and verified FileId/volume/root handles must
be studied and independently reviewed before integration.

### W21 follow-up: second process (detached evidence child of 67c850c)

Run this **different, non-canonical** Node 22 laboratory explicitly:

```sh
node --test experiments/issue-67-pr298-unbound-name-evidence/w21-second-process.cjs
```

Its six cases comprise three legitimate positive flows and **three EXPECTED
SECURITY RED** attacks. Each attack uses a separately forked, native Node
process: a different PID and an assert-equal actual Windows process **SID**
(from `whoami /user`) or POSIX **UID**. The parent intercepts the actual
`fs.promises.link/rename` call immediately before invoking the kernel; the
attacker child receives an IPC message, physically renames the originally
selected file and creates a *different* foreign synthetic inode at the
original name, opens and retains its own foreign FD, acknowledges IPC, and
the parent then invokes the **real** kernel syscall. The parent separately
holds the original FD. Assertions check `dev/ino`, bytes and child FD
identity after the syscall. The second process persists through the
attestation and is released before controlled fixture cleanup.

- **Progress**: actual final name aliases the child's foreign inode,
  not the original fsynced progress inode. Baseline positive publishes the
  intended original inode when there is no race.
- **Stage**: actual trash name contains the child's foreign inode, not the
  originally selected inode. Baseline positive retains correct bytes.
- **Historical `_apply`**: actual local target hardlinks the child's
  foreign inode. Crucially, the **existing** signed `_pushPending` SHA check
  returns `restore_local_materialization_missing` and **zero** remote pushes;
  it protects remote dispatch, not the already wrong local materialization.
  The baseline genuine Ed25519-authorized restore still pushes correctly.

The deterministic IPC rendezvous proves a **real same-UID/SID competing
process**, not just same-process filesystem API mutation. It still does
not prove every adversarial scheduler interleaving, cross-user process,
original-A→B→A handle provenance, durable root custody, independent owner
authority, or crash safety. `6/6 PASS` means all three vulnerabilities
were demonstrated alongside three legitimate positives, **not security
GREEN**. These are disposable synthetic artifacts; no third-party files
are accessed, and held FDs are closed before teardown.

### Additional native *prototype* proof: handle-bound no-replace linking

Both following **standalone** programs are runnable only as laboratory
demonstrations. Neither is linked into `sync-client`; neither is a
production API, supported portable dependency, root authority, or
release gate. Compile into a disposable directory, never commit binaries:

**Linux / ext4, with `TMPDIR` pointing to the real ext4 home filesystem:**

```sh
g++ -std=c++17 -O2 -Wall -Wextra \
  experiments/issue-67-pr298-unbound-name-evidence/w21-posix-fd-link-lab.cpp \
  -o /tmp/rootark-w21-posix-fd-link-lab
TMPDIR=/home/<linux-user> /tmp/rootark-w21-posix-fd-link-lab
```

The program holds source `fd` and destination directory `dirfd` while
its independently forked **same-UID second process** renames the original
pathname and installs unrelated bytes at that name. Linux
`linkat(sourcefd, "", dirfd, "published", AT_EMPTY_PATH)` is attempted
first; where the unprivileged process lacks the required capability, the
test uses the kernel-owned `/proc/self/fd/N` descriptor symlink with
`linkat(..., AT_SYMLINK_FOLLOW)`. It verifies that the final name contains
the **original** inode and bytes, the foreign inode remains intact, and
linking a second time fails with `EEXIST` (no-replace).

**Windows / NTFS x64, using the local .NET Framework C# compiler:**

```powershell
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:exe /platform:x64 /out:"$env:TEMP\rootark-w21-win-handle-link-lab.exe" experiments/issue-67-pr298-unbound-name-evidence/w21-win-handle-link-lab.cs
& "$env:TEMP\rootark-w21-win-handle-link-lab.exe"
```

The C# program opens the source's NTFS `HANDLE` and a **parent
directory HANDLE**, then launches a true same-SID Windows child process
which swaps the pathname and retains the foreign file's handle. It calls
`NtSetInformationFile(FileLinkInformation = 11)`, with a
`FILE_LINK_INFORMATION` containing `ReplaceIfExists = 0`,
`RootDirectory = heldDirectoryHandle` and a single relative leaf.
It compares the real `FileIdInfo` of the published, original, retained
and foreign handles; the original bytes are linked, the foreign bytes
remain, and a duplicate destination returns `STATUS_OBJECT_NAME_COLLISION`.
Do **not** confuse NT's `FileLinkInformation` with Win32
`FILE_INFO_BY_HANDLE_CLASS`: there is no Win32 `FileLinkInfo` class.

**Passing either native laboratory is not enough to call PR298 fixed.**
It proves a real original-held source and destination parent can be used
for *one* atomic no-clobber link. It does not prove that the handles were
the originally authorized RootSession, that a trusted external operator
retains immutable root/parent identities, that another writer cannot
mutate file contents in place or a mapped view, that source temp cleanup
cannot delete an unrelated inode, or that a full crash/restart sequence
retains no-duplicate signed authority and correct durability. Native
directory-relative **rename** and identity-scoped cleanup must be designed
separately; a complete change needs a cross-platform implementation,
independent SOURCE reviews, negative/positive cross-process regression,
CodeQL and the mandatory release gate. Until then **PR298 SOURCE NO-GO**.
