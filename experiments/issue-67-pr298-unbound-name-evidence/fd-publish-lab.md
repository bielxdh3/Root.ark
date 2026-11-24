# PR #298 / Issue #67: Linux ext4 held-FD no-replace publication LAB

**Scope:** synthetic, Linux-only native evidence built on local `67c850c11e56b945309aae75973ca0813257c392` (the original W21 RED lab). **NO-GO for product integration, merge or release.** The existing application paths, Windows implementation and historical worktrees are unchanged.

Run from the detached lab worktree on WSL2 Ubuntu with **Node 22** and **g++** installed:

```sh
cd /mnt/e/servidor/.worktrees/mission-20261111-pr298-w1-fdlink-ext4-20261111
findmnt -T /home/bielx -n -o FSTYPE # ext4 in this observation
TMPDIR=/home/bielx node --test experiments/issue-67-pr298-unbound-name-evidence/fd-publish-lab.cjs
```

The test compiles `fd-publish-linux.cpp` using `g++ -std=c++20 -O2 -Wall -Wextra -Werror` into its disposable **ext4** build directory. It runs its synthetic fixtures on that ext4 filesystem, *not* the source checkout's `/mnt/e` drvfs. Nothing is installed or linked into production. The adversary `fd-publish-adversary.cjs` runs in a **second Linux process with the same UID**, renames the open source to a retained alias and replaces the old source name with a distinct foreign inode. The test checks real `stat` `dev/ino`, bytes, child PID/UID, and no-clobber outcomes; the native helper waits on a test gate immediately before its real `linkat` syscall.

## Native algorithm and observed results

Node passes a previously opened regular source FD and previously opened directory FD to the compiled child as **3 and 4**, respectively. The C++ helper accepts **only a basename**, checks `fstat` types and same device, calls `fsync(sourceFd)`, and waits for the adversary gate. It first calls `linkat(3, "", 4, basename, AT_EMPTY_PATH)` to publish the inode referenced by the source descriptor with no replacement of an existing destination. Because unprivileged Linux can refuse `AT_EMPTY_PATH`, on `EPERM`, `EACCES`, `ENOENT`, `EINVAL` or `EOPNOTSUPP` it retries using `linkat(AT_FDCWD, "/proc/self/fd/3", 4, basename, AT_SYMLINK_FOLLOW)`. The latter uses Linux's procfs **magic link to the held source FD**, rather than an attacker-swappable source pathname; this fallback requires trusted Linux procfs at `/proc`. An unrelated error fails closed. A successful publication calls `fsync(dirfd)` before reporting `PUBLISHED`.

The helper **never calls `unlink`, `unlinkat`, `rename` or any pathname cleanup**. If the final directory `fsync` fails, it returns exit 85 with `published=1` and **durability unknown**; callers must not infer that deleting a pathname would remove the same inode. Existing destination returns exit 17 (`EEXIST`) without clobber or removal. Only synthetic test fixture directories are torn down after held FDs are closed.

Observed on **WSL2 Linux 6.18.33.1 / Ubuntu g++ 15.2.0 / Node v22.22.1 / `/dev/sdd` ext4**:

| Evidence | Physical outcome |
| --- | --- |
| Positive held source | Original inode + exact fsynced bytes published, `nlink=2` |
| `O_TMPFILE` unnamed source | Published same inode and contents, `nlink=1`; attempted `AT_EMPTY_PATH` returned **`ENOENT` (2)**; **fallback `PROC_SELF_FD`** succeeded |
| **RED** old `fs.promises.link(sourcePath, final)` with a different-process swap | Publishes **foreign** `dev/ino` and foreign bytes, while held original stays at retained alias |
| **GREEN** C++ publication after the *same* swap | Publishes **held original** inode and bytes via `PROC_SELF_FD`; foreign source and retained alias remain untouched |
| **GREEN** destination ancestor renamed/replaced by attacker | Published inside the *original* held destination `dirfd`; decoy directory stays empty |
| Existing destination + adversarial source swap | `EEXIST` exit 17; original destination identity/bytes unchanged; no cleanup |
| Invalid destination basename (`../escaped`) | Rejected before publication; no outside file created |

Test run: **7 passed / 0 failed**. All success results refer to a controlled disposable LAB. `AT_EMPTY_PATH` was **attempted but was not the successful mechanism on this WSL environment**; errno 2 is an observation, not proof of the cause. The fallback is the demonstrated real native descriptor-based publication path.

## Security and product limits

- A same-UID attacker with write access to the **original inode** (or an existing hardlink or the publishing process's `/proc/<pid>/fd`) can still change its bytes after `fsync`; holding an FD binds identity, **not immutable content**. There is no independent, unforgeable custody of the original inode, original directory ancestry, owner, or historical restore authority here.
- A same-UID process can replace destination entries **after** publication and might access/alter the original directory through other capabilities. `fsync(dirfd)` is a checkpoint for that directory, not a global anti-rollback lease or proof against concurrent adversarial writers and power failure. No crash/restart recovery protocol is implemented.
- The POSIX `stageExisting` rename and historical `_apply`/progress cleanup by mutable names remain unmodified and unsafe against source replacement. A production fix requires identity-bound staging, authority and lifetime management and a strategy for ambiguous publication and cleanup. This lab does not authorize a restore, a remote push, an operator election, or a merge.
- The native helper is Linux-specific, depends on `linkat`/ext4 and a usable trusted `/proc` fallback in unprivileged environments. Nothing has been compiled/tested for Windows, other filesystems, different UID or sandbox policies, seccomp restrictions, mount namespaces, or physical crash/power-loss conditions.

The parent RED evidence remains in `w21-races.cjs`. The new lab intentionally lives beside it and is not imported by runtime or automatically discovered by the normal test suite.
