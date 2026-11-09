# PR #298 / issue #67 — held-root rollback feasibility, worker-1 (local, no publication)

## Source and boundary

- Published Draft head at investigation: `b412ff378202feb90c70c5a100f7a8f2b683a08e` (parent `b98f0cf1a57a9d7ded16ceb3c0269e898f57d096`).
- Formal GHAS CodeQL run `129162890153`: **FAILURE, two HIGH** in `sync-client/rootark-sync-engine.js:401` and `:2604`. These are not dismissed or suppressed.
- Existing read-only native experiments are `scripts/issue-67-native-contained-open.cpp`, `scripts/issue-67-native-contained-read-win.cpp`, and `scripts/issue-67-native-contained-read-posix.cpp`; see `docs/validation/2026-11-09-issue-67-native-read-w35.md` for their prior coverage. None is authorized to mutate restore destinations.
- Existing independent `test/issue-67-w49-concurrent-parent-move.red.test.cjs` in the W49 worktree exposes destructive simultaneous rollback. It remains intentionally RED and untouched.

## New, narrower experiment

`test/issue-67-rooted-directory-lease-semantics.lab.test.cjs` performs only disposable native filesystem operations, with a second, independent process attempting the parent rename. Run it *explicitly* with `ROOTARK_ISSUE67_FD_LEASE_LAB=1`; ordinary `node --test` discovery skips both cases without compiling native programs.

On WSL2 Ubuntu with ext4 `/home`, a small C helper holds an `O_PATH|O_DIRECTORY|O_NOFOLLOW` directory fd, then waits. A second PID renames that directory **outside the selected root**, and creates a foreign file at the original pathname. The held helper successfully calls `openat2(dirfd, "new.dat", O_CREAT|O_EXCL|O_NOFOLLOW, RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV)` and writes to a **different new file in the relocated directory outside the original root**. The foreign inode at the old pathname is preserved. This proves that `RESOLVE_BENEATH`, `O_EXCL`, and `openat2` are relative to the **held directory object**, not proof of its continuing namespace ancestry.

On actual Windows `E:` NTFS, the existing bounded native `NtCreateFile(RootDirectory, ...)` reader holds the chain of root and ancestor handles without `FILE_SHARE_DELETE`. A separate PID attempting to rename the held `subdir` receives a sharing/permission denial; original bytes remain intact. This is a useful **live handle lease**, but its duration ends with the native process. It has no independent owner-signed physical root authorization or durable rollback transaction.

## Physical results

| Environment | Focused opt-in lab | Existing native-open gate |
| --- | --- | --- |
| Windows Node `v22.23.3`, real `E:` NTFS, MSVC + Windows SDK | **1 PASS, 1 platform SKIP** | **10 PASS** including 8 filesystem subtests, mapped writable section, writer, hardlink, stale root ID, junction and rename |
| WSL Ubuntu Node `v22.22.1`, native ext4 `/home`, GCC (`cc`) | **1 PASS, 1 platform SKIP** | Not rerun on WSL in this experiment |
| Default unconfigured discovery, both OS | 2 deliberate SKIPs; no compilation or filesystem fixtures | Existing coverage unchanged |

## Security decision — NO-GO for production restore

1. **Windows:** held ancestor handles can block ordinary namespace renames *while alive*, but there is no independently authorized trusted-root handle transferred and retained across all restore operations, including deletion/replacement, and no certified DACL/ACL custody, pre-existing writable mapping freeze or persistent transaction journal. The source tests do not establish a crash-safe replacement or DELETE protocol.
2. **Linux:** a held directory fd prevents neither parent `rename` nor external relocation; a subsequent fd-relative `openat2(O_EXCL)` can still create a file outside the originally authorized root. Final `fstatat` path checks are not an atomic namespace lock. `openat2` mitigates path traversal and symlinks but does not provide mutation-custody or writer exclusivity.
3. **Both:** no owner-signed root fingerprint, no durable independent inode ownership grant, no complete staged-preimage historical recovery for `nlink=2`, no journal/metadata flush semantics across crash, and no secure way to delete or replace a present foreign inode atomically under this design.

**Do not wire any experimental helper into `restoreFileSet`, clear GHAS, change `recovered:true`, or publish a partial fix.** The sole intended artifact is a reproducible OS-semantic proof for independent review; W49 and prior RED labs remain intact.
