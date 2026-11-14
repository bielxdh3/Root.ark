# PR #298 / Issue #67 — NTFS held-HANDLE no-replace publication LAB

**Source:** detached child of Linux LAB `35e47bf7625098a503b3d9b74f9ee93578d48fa2` (which remains intact). **Status: LAB evidence only; production/merge/deploy NO-GO.** No application call sites were modified or enabled. This is a synthetic Windows-native helper and explicit Node test, not a Windows 10 CFAPI/Files On-Demand implementation or a production recovery writer.

## Build/run (Windows, PowerShell, from this worktree)

The machine has Visual Studio Community **2026 Insiders** with MSVC `cl.exe` (v14.51) and Windows SDK `10.0.26100.0`. `E:` is NTFS. The `.toolchains` repository directory contains Android tooling, not the Windows compiler. `build-held-link-win.cmd` loads the installed `VC\Auxiliary\Build\vcvars64.bat` and compiles with MSVC `/W4 /WX /std:c++17` into a disposable local `.lab-bin` directory. Provide a real Windows **Node 22** binary as `$env:ROOTARK_NODE22`; the run used v22.23.4 from an existing local npm cache.

```powershell
$lab = 'experiments\issue-67-pr298-unbound-name-evidence'
New-Item -ItemType Directory -Force '.lab-bin' | Out-Null
& "$lab\build-held-link-win.cmd" (Join-Path (Get-Location) '.lab-bin\held-link-win.exe')
$env:ROOTARK_NTFS_LINK_LAB_BINARY = (Join-Path (Get-Location) '.lab-bin\held-link-win.exe')
$env:ROOTARK_NTFS_LINK_LAB_TMPDIR = (Join-Path (Get-Location) '.lab-bin\fixtures')
& $env:ROOTARK_NODE22 --test "$lab\held-link-win-lab.cjs"
```

The test requires its disposable fixtures on **E: NTFS** and verifies this drive selection. It does not run through production `npm test`; generated `.exe`/`.obj` are not committed. The normal lab teardown applies only to disposable test-owned directories, after tests finish. The C++ publisher itself contains **no delete/rename/unlink or cleanup by uncertain path**.

## Native operation and physical adversary

`held-link-win.cpp` opens and **holds** a regular source file `HANDLE` and a destination **parent directory `HANDLE`**, with sharing that permits a same-SID concurrent actor to rename both original pathnames. It checks `FileIdInfo` (128-bit file identifier and `VolumeSerialNumber`), non-reparse attributes, same volume and NTFS on the held directory. It calls `FlushFileBuffers(source)` **before** reporting `READY`. The test's native child waits until a **second real Windows process, same SID verified through `whoami /user`,** renames the source to a retained alias, creates foreign bytes under the original source pathname and optionally renames/replaces the destination ancestor. The parent process then releases the gate for the native mutation.

The Windows SDK headers in this installation do **not** expose the Win32 `FileLinkInfo`/`FILE_LINK_INFO` class. The helper therefore calls `NtSetInformationFile(FileLinkInformation=11)` using a private `FILE_LINK_INFORMATION` compatible layout with `ReplaceIfExists=FALSE`, the *already-held* directory `RootDirectory`, and a restricted single-component basename. There is no precheck followed by JavaScript `rename`. After publication, `NtOpenFile` uses the **same held `RootDirectory`** to open the published leaf; its `FileIdInfo` must match the source `FileIdInfo` and volume, even if the former parent path now resolves to a decoy. Existing destination returns `EEXIST` (exit 17); it is not overwritten.

The last action is `FlushFileBuffers(parent)`. On the observed NTFS setup both source and parent calls **returned success** (`source_flush=ok parent_flush=ok`). If a post-publication verification or parent flush fails, the process returns **exit 85, `published=1`, `durability=unknown`** without deleting anything. `ROOTARK_LAB_FORCE_PARENT_FLUSH_FAILURE=1` is a LAB-only fault injection after physical link publication; the adversarial test confirms this ambiguity is reported and foreign/original names survive. Success of `FlushFileBuffers` means the OS accepted the flush call, **not proof of power-loss persistence** or protection against other writers.

## Recorded validation

**Host:** Windows 11 Pro **10.0.26300**, E: **NTFS**, Visual Studio 18 Insiders MSVC 14.51, Windows SDK 10.0.26100.0, **Node v22.23.4**. Native MSVC compilation `/W4 /WX` passed; `node --check` passed for both new `.cjs` files. Test run: **7/7 PASS, 0 FAIL**:

| Scenario | Physical result |
| --- | --- |
| Positive | Held source FileId == destination FileId; exact source bytes; both flush calls returned success |
| **Expected RED** path-based `fs.promises.link()` | After real second-process source-name replacement, publishes **foreign** NTFS `dev/ino` and bytes; retained original differs |
| **GREEN** native source HANDLE | Same second-process replacement publishes **original** FileId/bytes through held source; foreign source remains intact |
| **GREEN** held destination RootDirectory | After second process moves original parent and creates decoy path, publishes under **original held directory**, decoy remains empty |
| No-replace / `EEXIST` | Pre-existing foreign destination FileId/bytes and substituted source remain unchanged; native exit 17 |
| Post-publication checkpoint fault | Native exit 85 and `published=1 durability=unknown`; published original FileId, retained original and foreign replacement survive; no pathname cleanup |
| Invalid destination `..\escaped.bin` | Exit 2 before mutation; nothing published outside destination |

**WSL2 regression** from the inherited Linux LAB: `TMPDIR=/home/bielx node --test experiments/issue-67-pr298-unbound-name-evidence/fd-publish-lab.cjs` on ext4, g++15.2, Node v22.22.1: **7/7 PASS, 0 FAIL**. Its native publication still uses `/proc/self/fd` fallback (`AT_EMPTY_PATH` returned `ENOENT (2)`), as documented in the Linux LAB.

## Explicit security and product limitations

- Tested **Windows 11 build 26300**, **not Windows 10**; **no CFAPI**, Windows 10 Files On-Demand behavior, crash/power-cut, actual reboot replay, antivirus interference, multi-volume or alternate filesystem guarantee was tested.
- Retaining file/directory handles binds object identity for this narrow publish syscall, **not immutable contents, an independently trusted root FileId, custody, ACL authority, or a protected lifecycle**. A same-SID adversary with a writable source handle, another hardlink, mapped section, or appropriate rights may modify bytes even after flush. The adversary remains free to change names after publication.
- `NtSetInformationFile` is a Windows NT-specific operation; its accepted behavior on this tested system cannot be extrapolated to all Windows installations. A production change needs compatibility review, root identity trust and policy binding, staging/removal without mutable pathnames, interrupted-operation state management, physical restart recovery and independent security review.
- The original PR298 product flows (`createDurableRestoreProgress`, historical restore `_apply`, and `stageExisting`) remain **unchanged**. This lab authorizes no restore, remote push, production I/O, release or merge.
