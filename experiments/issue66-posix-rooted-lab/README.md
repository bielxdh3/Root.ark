# Issue #66 — W3 POSIX root-relative I/O laboratory (test-only)

**Status: source/prototype GO within this disposable Linux ext4 experiment;
system/release NO-GO.** This is an independent milestone branched from
`c01014735a438bf27bf5e2a346af7930993b5f97`. It makes no changes to
production Root.ark / CFAPI / SyncEngine / RootSession / Root/main.

## Physical execution

From the dedicated worktree, on **WSL Ubuntu Linux ext4 with gcc and Node 22**:

```sh
ROOTARK_ISSUE66_POSIX_LAB=1 node --test test/issue-66-w3-posix-rooted-lab.test.js
```

No opt-in means the entire suite skips. The Node harness requires WSL, Node 22,
a canonical HOME on **ext4** (not /mnt/e DrvFS and not /tmp tmpfs). It creates
random, private, initially empty `rootark-w3-posix-*` directories directly
under the running user's HOME. The C helper refuses a disabled opt-in,
nonempty scratch, invalid scratch names, other parent paths, and a non-ext4
filesystem. Fixtures stay in HOME for inspection: **no recursive teardown** and
no arbitrary filesystem cleanup. Re-running the bulk test creates another
16,385 disposable entries, so run it only when necessary.

The harness compiles the checked-in **C source** with gcc `-Werror`; its
executable is placed in a randomized **/tmp** build directory, never inside the
repository, and is not tracked in Git. There are no changes to application
packages or runtime entry points. Normal native outputs are single fixed
categorical lines, with no source paths, inode IDs, content, credentials or ACLs.

## What the code actually does

1. It holds an independent `O_PATH|O_DIRECTORY` handle on namespace `/` and
   obtains the HOME **parent** dirfd using `openat2` with
   `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV`. It opens the
   randomized scratch leaf under that parent with the same flags. All later
   accesses to protected fixture entries are relative to these FDs.
2. It creates the held directory and marker with `mkdirat` and `openat2`,
   uses `fdopendir` on the **exact original fd**, reads/hashes both the trusted
   and replacement marker through `openat2`, and checks dev/inode identities.
   A Unicode filename (`café-中-😀.bin`) is read and enumerated byte-exact;
   no case or normalization conversion is performed.
3. An adversarial *deterministic namespace sequence* renames original **A**
   from `held` to `parked`; creates replacement **B** at `held` with
   a different marker; verifies no-replace failure (`EEXIST`); moves B to
   `foreign-parked`; and restores A under `held`. Every rename uses
   `renameat2(..., RENAME_NOREPLACE)` with **the same scratch dirfd**. The
   pinned A descriptor reads the original bytes throughout, and B retains its
   independent content. Negative `openat2` checks reject symlink traversal
   (`ELOOP`) and parent escape (`EXDEV`).
4. Only a newly created, fixed-name `disposable.delete` file is deleted with
   `unlinkat` relative to pinned A; `fsync` runs for marker files and
   the affected directory FDs. There is **no recursive deletion**, and neither
   the original nor replacement fixture trees are removed.
5. A separate 16,385-entry case creates Unicode-suffixed entries with
   `openat2(O_CREAT|O_EXCL)`, enumerates them in streaming fashion through
   `fdopendir` on that same directory fd, rejects unexpected names and counts,
   and `fsync`s the directory. Memory is bounded independently of entry count.

## Verification (local, 2026-11-09)

Platform: WSL Ubuntu, Linux 6.18.33.1, **ext4 HOME**, Node **v22.22.1**,
gcc **15.2.0**. Before the C source existed, the Node tests reported
**0 PASS / 3 FAIL / 1 SKIP** (intentional TDD RED: gcc build unavailable).
After compiling the C source, the same opt-in tests reported:

```text
3 PASS / 0 FAIL / 1 SKIP
ROOTARK_POSIX_V1 stage=CORE fs=EXT4 parent=INDEPENDENT_FD openat2=STRICT aba=PASS noReplace=PASS marker=PASS unicode=PASS unlink=PASS fsync=PASS
ROOTARK_POSIX_V1 stage=BULK fs=EXT4 entries=16385 enumeration=SAME_FD unicode=PASS fsync=PASS
```

The fourth test is an **explicit bind-mount adversary SKIP**. The executing
WSL user had `CapEff=0` and therefore lacks `CAP_SYS_ADMIN`. No bind mounts,
privileged mount namespaces, or foreign filesystems were modified.

## Limits: why system-level NO-GO remains

The OS `/` handle is a namespace starting point, **not independent application
authority**. The HOME path, initial scratch creation by the JS harness, and
the application/process itself are not attested by a separately trusted owner.
Same-UID adversaries who can mutate the parent or scratch can still race the
first acquisition or replace names **between** `renameat2` steps. This
deterministic sequence is evidence of object identity on one ext4 host; it is
not a concurrent malicious-process test or an atomic multi-step transaction.

`RENAME_NOREPLACE` protects one destination from overwrite, not the entire
namespace against ABA, ancestor replacement, or competing writers.
The lab does not cover independent custody, cold reacquisition after process
exit, cross-mount/bind-mount adversaries, mount-namespace manipulation,
system crash/power-cut durability, directory-journal checkpoints, full 16,385
entry recovery, or production authorization. Individual bulk file contents
are not `fsync`ed; an `fsync` of a directory is not proof of whole-tree
power-loss durability. The positive Unicode case checks exact UTF-8 bytes,
not all normalization/collision variants.

**Decision:** preserve as a **test-only proof**, request independent source
review, and retain **NO-GO for production/release/PR #300** until authentic
root authority, hostile concurrency, mount boundaries, crash recovery and
admission semantics have separate evidence.
