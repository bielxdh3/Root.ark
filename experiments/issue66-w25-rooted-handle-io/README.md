# Issue #66 / PR #300 — W25 native rooted file-I/O proof (test-only)

**Scope:** A deliberately narrow, opt-in Windows/NTFS experiment; not a CFAPI
release change, not an ACL trust root, not a process launcher and not a fix for
CodeQL. Parent source baseline: `609564fa041cd903c6641368dd8df14d86f1442e`.

The test adds no native `.exe` or binary helper to the repository. It invokes a
checked-in PowerShell test script that compiles embedded C# interop with
`Add-Type` and uses `NtCreateFile` with an existing directory `HANDLE` as
`OBJECT_ATTRIBUTES.RootDirectory`. All **protected** file creation, writing,
flushing, reading and deletion in the experiment use native root-relative file
handles. **Pathname-based writes do occur** during the disposable fixture's
initial setup (`fs.mkdtempSync`, `Directory.CreateDirectory`, owner-only DACL
`Directory.SetAccessControl`), adversarial rename/replacement/canary setup,
and postcondition verification. Automatic recursive cleanup was removed
from this candidate; the initial root in the original lab is
also opened by `CreateFileW` using an absolute path. These steps are explicitly
OUTSIDE the protected post-open file-I/O boundary; there is no fallback from
a failed rooted file operation to a new absolute filename.

Run on a real Windows 10/11 NTFS host with Node 22:

```powershell
$env:ROOTARK_ISSUE66_W25_NATIVE_IO_LAB='1'
node --test --test-reporter=tap test/issue-66-w25-native-rooted-io-lab.test.js test/issue-66-w25-native-rename-identity.test.js
Remove-Item Env:ROOTARK_ISSUE66_W25_NATIVE_IO_LAB
```

By default both tests skip. The opt-in script only accepts a randomized
`rootark-w25-native-rooted-io-*` test directory **directly under the current
user's LocalAppData**. It rejects arbitrary external paths and requires the
exact opt-in variable. This is *not* an endorsement of TEMP as a trust anchor:
the Windows `E:` checkout test initially failed closed when attempting to
write an owner-protected DACL (`UnauthorizedAccessException`); the isolated
disposable LocalAppData fixture permits the DACL operation. The fixture creates
an owner-only protected root; only test-created files are affected. In this
hardened candidate both Node test runners deliberately **retain** their
disposable LocalAppData fixtures: recursive pathname teardown could delete an
unrelated replacement tree after an ABA swap. Inspect before any manual
cleanup, and never clean these names while a competing actor can replace them.

## What a physical PASS demonstrates

1. Open the real NTFS directory with `CreateFileW` and retain its valid handle.
   Verify directory/non-reparse/NTFS via this handle.
2. Create `original.bin` relative to that directory with `NtCreateFile`
   (`RootDirectory`, one fixed filename, no reparse traversal). Write and flush
   its content through the opened file handle.
3. **Actually rename the directory while its handle remains open**, then
   create a new directory at its former pathname containing a same-name
   `FOREIGN_CANARY` file.
4. Open and read `original.bin` *relative to the old directory handle*: only
   the original content is returned. Delete the original file with
   `SetFileInformationByHandle(FileDispositionInfo)` on a rooted-opened handle.
   The different `FOREIGN_CANARY` remains unchanged.
5. Create/write/flush/reopen/read/delete `after-swap.bin` relative to the old
   handle. It appears exclusively in the moved original, never in the new
   same-spelled directory, and its cleanup does not touch the replacement.
6. No path, SID, ACL, file bytes, compiler errors or other internal data are
   printed. Success and rejection outputs use fixed categorical strings.

**Observed local Windows Node v22.23.3/NTFS:** 2 PASS / 0 FAIL / 0 SKIP on
the explicitly opted-in lab. Test 1 exercises the actual syscall sequence;
test 2 verifies that arbitrary TEMP scratch and disabled opt-in are rejected,
leaving a foreign canary unmodified. An eligible-looking, **nonempty**
LocalAppData directory containing an unrelated owner canary is also rejected
unchanged. Ten consecutive separate Node 22 opt-in executions passed on the
earlier baseline. The original #300 native ACL test trio remained 13 PASS /
0 FAIL without opt-in; the two new lab tests were correctly SKIP. WSL Ubuntu
Node 22: 2 expected Windows-only SKIP / 0 FAIL.

## Independent native HANDLE identity / rename reconciliation (W42 P2)

The independent `test/support/issue-66-w25-native-rename-identity.ps1` does
not reuse the original lab's C# interop and adds **no executable files**. It
requires **NTFS** from the retained scratch handle through
`GetVolumeInformationByHandleW` plus a fixed local drive through
`GetDriveTypeW`. It creates/reopens fixture directories
through `NtCreateFile` relative to that handle. It performs four bounded
physical Windows/NTFS cases, with both `.NET
Directory.Move` and direct native `MoveFileExW`. `NtCreateFile` opens each
tested root with share mask **3** (`FILE_SHARE_READ | FILE_SHARE_WRITE`,
**no FILE_SHARE_DELETE**) or **0** (no sharing). `CreateFileW` initially
opens the scratch anchor with share mask 7. It checks the root's `HANDLE` validity
before and after rename and uses real `GetFileInformationByHandleEx(FileIdInfo)`
volume/file identities. An old handle maps to **O1** before and after rename;
the moved name also maps to **O1**, whereas a newly created replacement at
the old absolute pathname maps to a *distinct* **O2**. A native
`NtCreateFile(RootDirectory=oldHandle, 'child')` returns `NTSTATUS=0x00000000`
and maps to the original child, not the replacement child.

Categorical Windows/NTFS outputs expected by the updated Node 22 test
(mapped ephemeral identifiers, no raw file IDs, paths, security principals,
ACLs, or user data):

```
ROOTARK_W25_RENAME_V2 mode=DOTNET share=3 filesystem=NTFS storage=LOCAL handle=VALID move=SUCCESS win32LastError=NA_DOTNET ntstatus=0x00000000 rootBefore=O1 rootAfter=O1 moved=O1 replacement=O2 child=ORIGINAL
ROOTARK_W25_RENAME_V2 mode=WIN32 share=3 filesystem=NTFS storage=LOCAL handle=VALID move=SUCCESS win32LastError=0 ntstatus=0x00000000 rootBefore=O1 rootAfter=O1 moved=O1 replacement=O2 child=ORIGINAL
ROOTARK_W25_RENAME_V2 mode=DOTNET share=0 filesystem=NTFS storage=LOCAL handle=VALID move=SUCCESS win32LastError=NA_DOTNET ntstatus=0x00000000 rootBefore=O1 rootAfter=O1 moved=O1 replacement=O2 child=ORIGINAL
ROOTARK_W25_RENAME_V2 mode=WIN32 share=0 filesystem=NTFS storage=LOCAL handle=VALID move=SUCCESS win32LastError=0 ntstatus=0x00000000 rootBefore=O1 rootAfter=O1 moved=O1 replacement=O2 child=ORIGINAL
```

`win32LastError=0` is the actual `Marshal.GetLastWin32Error` returned following
`MoveFileExW` on this machine; **GetLastError is not a meaningful independent
security guarantee when the Win32 call succeeds**. `.NET Directory.Move`
does not supply a corresponding direct native last-error, so its value is
`NA_DOTNET`. The `NTSTATUS` is the actual return from rooted `NtCreateFile`.
These findings prove that omitting `FILE_SHARE_DELETE` **does not by itself
prevent a rename on the tested Windows host**; existing open handles continue
referring to their original objects. The four-mode test rejects failure to
move, same-ID replacement, handle invalidation, and misrouted relative opens.

**Candidate hardening, locally validated:** after a RED test for the missing
NTFS marker, Windows NTFS Node **v22.22.1: 4 PASS / 0 FAIL / 0 SKIP** across
both W25 test files; WSL Ubuntu Node **v22.22.1: 4 expected Windows-only
SKIP / 0 FAIL**. No external-path fixture, malicious concurrent process,
or destructive cleanup was executed. The test suites retain disposable
LocalAppData directories for later manual review.

## Still NOT established (release NO-GO)

- **W25 P2-A remains open:** the .NET and Win32 rename operations still
  accept absolute *pathname* source/target names. A second process under the
  same user can swap the scratch name after the handle/path identity check
  but before either rename. This can cause a mutation of an unrelated entry
  and cannot be ruled out with pre/post pathname checks. The helper now
  pins the scratch HANDLE, checks its FileIdInfo before and after renames,
  uses root-relative opens/creation for its children, and **never recursively
  deletes** any path, reducing impact without an atomic security guarantee.
  **SOURCE NO-GO for this adversarial safety property.**
- **W25 P2-B addressed at source and on real local NTFS:** the independent
  helper checks `GetVolumeInformationByHandleW` against `NTFS` and
  `GetDriveTypeW` against `DRIVE_FIXED` on its retained scratch handle.
  No negative non-NTFS or remote volume
  was physically exercised; the implementation is fail-closed on a failed
  query or a different filesystem label.
- Initial, authentic root acquisition: opening the root by pathname could race
  *before* its first handle is obtained. There is no fully handle-rooted chain
  from a separately trusted owner/volume root here. An owner-only DACL does
  not exclude an adversary with the **same principal**, or an untrusted
  directory ancestor with `DELETE` rights.
- This result proves **non-escape of operations relative to the retained
  handle**, not persistence of the original *name*. A moved root can disappear
  from its discoverable pathname. A cold reopen under the old name can reach
  the replacement. No release ACK should rely on that without additional
  namespace custody/recovery semantics. A held handle with share=0 or share=3
  is NOT itself an anti-rename lock, as independently reproduced above.
- A `FileStream.Flush(true)` is not proof that directory names, journal
  checkpoint, or directory rename are durable after a Windows power cut.
  Atomic no-replace publication and reboot recovery are unimplemented.
- The lab does not securely bind the actual image launched via `CreateProcess`
  or `spawnSync`. A pre-spawn digest/inode check on `.exe`, `cmd.exe`, vcvars,
  or `cl.exe` and a static filename do not prove what bytes executed under
  hostile pathname swaps. W2 executable helper files are untouched.
- No independently attested Visual Studio toolchain, official CodeQL hosted
  verdict, real multi-user hostile rename exploit, end-to-end CFAPI
  registration, or production native transport has been exercised.

**Decision:** valid *test-only* primitive for review and future design work;
**SOURCE/operational NO-GO** for promoting PR #300 until independently reviewed
native root acquisition, ACL custody, cold-reopen namespace binding, executable
identity, crash-safe publication and Windows hosted CI are proven.
