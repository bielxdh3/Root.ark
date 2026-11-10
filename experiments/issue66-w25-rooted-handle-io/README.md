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

## New opt-in physical leaf substitution and handle deletion (V2)

Child `9302e3da` tests a **different race** from the outer-directory
replacement above: after a file is opened with native
`NtCreateFile(RootDirectory=retained A HANDLE)`, another same-SID
operation moves the original child and creates a distinct file at
its old name *inside A*. The lab also creates a canary under
replacement B at A's old pathname.

The helper uses a fixed `swap-leaf.bin` and `FILE_SHARE_DELETE`
to permit this real NTFS move while the original file HANDLE remains
open. A test-controlled `File.Move` moves that original to a parked
fixture-only name, then creates both foreign files. The helper calls
`SetFileInformationByHandle(FileDispositionInfo)` **on the original
opened file HANDLE**, not on either now-foreign pathname. After closing
the original handle it requires the parked original to be absent
and both foreign contents unchanged. A later pathname unlink of the
original name would instead delete the same-parent foreign file.
This is a native opened-inode deletion proof only for that schedule.

The categorical V2 requirement was **RED** against the old V1
helper because V1 did not test this case; the RED is a *missing
proof*, **not** a destructive exploit of the previous native
implementation. Physical Windows 11 / NTFS / Node v22.23.4:
**2 PASS / 0 FAIL** with explicit lab opt-in (including the negative
empty/nested/disabled scratch gate); Ubuntu WSL Node22:
**2 expected Windows-only SKIP**. No file outside the test-owned
LocalAppData fixtures was intentionally opened or deleted. The
fixtures are retained, never recursively cleaned by the helper.

The test's adversarial steps are **sequential in the same process
and SID**, not a separately scheduled hostile writer. Initial scratch
discovery and the adversarial `File.Move`/`WriteAllText` use
ordinary paths; a hostile same-SID actor could change that ancestry
before root acquisition. This does **not** establish independent
root authority, trusted same-SID isolation, cold restart, native
RootSession, Windows 10/CFAPI, rollback witness, directory powercut
durability or production secure deletion. **RELEASE NO-GO.**

## Independent native HANDLE identity / rename reconciliation (W42 P2)

The independent `test/support/issue-66-w25-native-rename-identity.ps1` does
not reuse the original lab's C# interop and adds **no executable files**. It
requires **NTFS** from the retained scratch handle through
`GetVolumeInformationByHandleW` plus a fixed local drive through
`GetDriveTypeW`. It creates/reopens fixture directories
through `NtCreateFile` relative to that handle. The new handle-rename
candidate exercises `NtSetInformationFile` with
`FileRenameInformation (10)` and `FileRenameInformationEx (65)`,
using the original source HANDLE, `RootDirectory=scratch HANDLE`
and fixed relative target `moved-ancestor`. There are four physical
Windows/NTFS combinations: each information class with source share mask
**3** (`FILE_SHARE_READ | FILE_SHARE_WRITE`, no FILE_SHARE_DELETE)
and **0** (no sharing). The source handle has `DELETE` access.
`CreateFileW` initially opens scratch with share mask 7. It checks root HANDLE validity
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
ROOTARK_W25_RENAME_V3 mode=INFO share=3 filesystem=NTFS storage=LOCAL handle=VALID rename=HANDLE move=SUCCESS renameNtstatus=0x00000000 ntstatus=0x00000000 rootBefore=O1 rootAfter=O1 moved=O1 replacement=O2 child=ORIGINAL
ROOTARK_W25_RENAME_V3 mode=INFO_EX share=3 filesystem=NTFS storage=LOCAL handle=VALID rename=HANDLE move=SUCCESS renameNtstatus=0x00000000 ntstatus=0x00000000 rootBefore=O1 rootAfter=O1 moved=O1 replacement=O2 child=ORIGINAL
ROOTARK_W25_RENAME_V3 mode=INFO share=0 filesystem=NTFS storage=LOCAL handle=VALID rename=HANDLE move=SUCCESS renameNtstatus=0x00000000 ntstatus=0x00000000 rootBefore=O1 rootAfter=O1 moved=O1 replacement=O2 child=ORIGINAL
ROOTARK_W25_RENAME_V3 mode=INFO_EX share=0 filesystem=NTFS storage=LOCAL handle=VALID rename=HANDLE move=SUCCESS renameNtstatus=0x00000000 ntstatus=0x00000000 rootBefore=O1 rootAfter=O1 moved=O1 replacement=O2 child=ORIGINAL
```

`renameNtstatus` is the actual result from `NtSetInformationFile`;
the separate `ntstatus` belongs to rooted `NtCreateFile` for the child.
The Win32 `SetFileInformationByHandle(FileRenameInfo)` probe with non-null
`RootDirectory` returned `ERROR_INVALID_PARAMETER (87)` on this Windows
host, so the final helper calls the NT service, which accepts the retained
parent handle and fixed relative filename. It has **no pathname fallback**.
Both native classes succeeded on the test host. This demonstrates that
omitting `FILE_SHARE_DELETE` does not alone prohibit renaming **by the
source handle**, under these narrow conditions. The four-mode test rejects
failure, same-ID replacement, invalidated handles and wrong relative opens.

**Candidate hardening, locally validated:** after a RED test for the missing
NTFS marker, Windows NTFS Node **v22.22.1: 4 PASS / 0 FAIL / 0 SKIP** across
both W25 test files; WSL Ubuntu Node **v22.22.1: 4 expected Windows-only
SKIP / 0 FAIL**. No external-path fixture, malicious concurrent process,
or destructive cleanup was executed. The test suites retain disposable
LocalAppData directories for later manual review.

**New handle-rename continuation:** the test was RED against pathname-based
rename code. An attempted Win32 handle rename rejected with error 87
(no path fallback); the equivalent native NT rename became GREEN on local
NTFS with both information classes. This evidence covers only the new
rename primitive and the existing identity comparisons. Windows Node
**v22.22.1: 4 PASS / 0 FAIL / 0 SKIP** with both W25 test files, including
four combinations of native rename class and share mask. WSL Ubuntu Node
**v22.22.1: 4 expected Windows-only SKIP / 0 FAIL**.

**Source CREATE-to-OPEN binding regression (P2, child of 5d5500):**
`test/support/issue-66-w25-native-rename-identity.ps1` now records the
original directory's full `FileIdInfo` (volume serial and 16-byte object ID)
*while the newly created source HANDLE is still open*. It verifies that
source is a plain non-reparse directory on the same volume as the scratch
HANDLE. The initial handle is then closed to permit the separate `share=0`
reopen; the reopened root must also be a plain non-reparse directory and
have exactly the recorded `FileIdInfo` before any tested rename. An
identity mismatch fails closed with exit **42**, no success output, and the
categorical error `ROOTARK_W25_SOURCE_ID_REJECTED`.

The opt-in negative test simulates this gap without an attacker or outside
path: retaining the original HANDLE, it uses `NtSetInformationFile` to move
the original fixture to `test-relocated-ancestor`, creates a distinct
`held-ancestor` beneath the *same pinned scratch HANDLE*, then releases
the original and reopens by name. It expects the identity rejection in all
four `INFO / INFO_EX × share 0 / share 3` combinations, verifies that
both fixture children remain present, and that `moved-ancestor` was
never created. No delete, cleanup, external directory or arbitrary leaf
is involved. TDD RED was observed: unpatched code returned successful
exit **0** against the new test's expected **42**. The source binding fix
made this deterministic test GREEN.

## Still NOT established (release NO-GO)

**W25 isolated read-only evidence (child of 76cfa21e):** opt-in
`test/issue-66-w25-native-held-read.test.js` invokes the existing guarded
PowerShell/C# helper on a fresh, empty test-owned LocalAppData NTFS scratch.
Via the pinned scratch HANDLE, it creates ancestor A and its Unicode marker
using `NtCreateFile(RootDirectory)` and `WriteFile` (fixture setup only).
The original A directory HANDLE stays open. It renames A out by HANDLE,
creates B under A's former name, and verifies *during B occupancy* that
`NtQueryDirectoryFile(FileNamesInformation)` enumerates exactly the original
UTF-16 filename and that `NtCreateFile(RootDirectory=A)` plus `ReadFile`
returns exactly A's UTF-16 bytes. B is independently enumerated/read and
verified to have different FileIdInfo and bytes. B is then renamed away
without replacement, the original A HANDLE is renamed back to its old name,
and A is enumerated/read again. The helper denies an existing-marker
`FILE_CREATE` collision, checks non-reparse file/directory attributes and
FileIdInfo, and returns only categorical proof fields. No filesystem content
is read via an absolute pathname, and no cleanup/deletion is performed.
TDD on Windows NTFS Node22: **RED** when the new contract was absent;
**GREEN 2/2** for the focused test and populated-scratch rejection.
The test does not execute a hostile same-SID process or establish initial
scratch custody, independent writer isolation, power-cut durability or
production CFAPI correctness: **SOURCE NO-GO for those properties** pending
an independent SOURCE peer review.

- **W25 P2-A rename primitive now handle-bound:** source and destination
  are native HANDLES retained before the rename, so the helper no longer
  resolves mutable source or destination pathnames for this operation.
  Relative destination is a fixed leaf and the rename refuses replacement.
  Its fixture creation/readback also uses root-relative native handles.
  There is no recursive teardown.
- **W25 initial trust acquisition remains SOURCE NO-GO:** the JS process
  creates scratch by pathname and PowerShell validates that pathname
  before obtaining the initial scratch HANDLE. A same-principal actor
  can swap the entry before acquisition; post-acquisition identity checks
  cannot establish independent ownership of that initial object. No
  adversarial race was executed. Do not claim the whole laboratory
  resistant to malicious same-user filesystem swaps.
- **W25 P2 internal source substitution is now covered:** source creation
  and its later reopen are linked by exact `FileIdInfo` and volume identity
  plus non-reparse checks. The test-injected same-scratch replacement fails
  before the normal `NtSetInformationFile` rename. This does **not** establish
  trusted acquisition of the scratch itself, nor prove safety under a
  concurrent hostile same-user process.
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
