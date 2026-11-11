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

**Next step**: native design and physical process-separated adversarial
RED→GREEN on both systems, including legal signed restore, no-clobber,
foreign-inode preservation, power-loss/restart semantics and CodeQL/CI.
Do not publish this as a source or release GO.
