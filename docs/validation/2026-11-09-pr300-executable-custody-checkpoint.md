# PR #300 — executable identity and native custody checkpoint (2026-11-09)

Status: **SOURCE / OPERATIONAL NO-GO** for release or fast-forward of the integrated
PR #300 work. This is an append-only local checkpoint, not a claim of completed
Windows Files On-Demand custody or recoverability.

## Exact scope and evidence

- Published #300 HEAD at the start of this checkpoint:
  `956b2515d3f5262b2bf8c6044be2bfd2db72dc9e`, OPEN/Draft.
- Local #300 receipt candidate: `be8d47fa14ceb383b856c8bad93d183166b191b9`.
  Independent SOURCE GO applies **only** to its test-only build receipt.
  Its `spawnSync(previous.executable)` and TEMP `build.cmd` remain
  pathname-based and cannot authenticate the actually executed image.
- Local child `d13fa8afba14c76c1da0e18bfe66120c4917aff2` pins
  `C:\Windows\System32\cmd.exe` and
  `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
  instead of selecting the system interpreters through PATH, in three
  CFAPI test files. New source regression test rejects PATH-resolved
  interpreters. RED before fix; GREEN after fix.
- Physical validation for the child: Windows Node 22 / NTFS **8 PASS,
  0 FAIL**, including real native SDK fixtures; Ubuntu WSL Node 22 /
  physical `/dev/sdd` ext4 **3 PASS, 5 expected Windows SKIP, 0 FAIL**.
  The strengthened static test also passed on both OSes.
- Independent exact-source peer classified `d13fa8af` as
  **SOURCE GO restricted to PATH-selection hardening**, not image trust,
  CFAPI operational readiness or release.

## Kernel image-identity experiment

Isolated scripts in `E:\servidor\.tmp\issue66-imagefilemapping-20261109`
used `CreateProcessW(CREATE_SUSPENDED)` and
`NtQueryInformationProcess(ProcessImageFileMapping=44)`, without resuming
the inspected process:

| File-handle comparison | NTSTATUS |
| --- | --- |
| Handle to actual image file | `0x00000000` (same) |
| Handle to a different executable | `0xC0000001` (different) |
| Handle pinned before a disposable executable leaf was renamed/replaced | `0xC0000001` (different) |

This demonstrates physical **image file-object comparison**, not an
authenticated digest of the image bytes eventually executed. The
information class is undocumented for stable application use. Its
`SectionObjectPointer` equality does not establish code/data section
equality, absence of preexisting writable mappings, trust in subsequently
loaded DLLs, or integrity of a mutable build script. A separate
ancestor-directory rename attempt returned AccessDenied in this probe;
do not cite that attempt as a successful ancestor-swap test. Attempts
to investigate a preexisting writable memory mapping did not complete
because of a sharing violation and are inconclusive.

## Explicit unresolved security gates

1. **Native executable trust:** `test/issue-66-cfapi-deny-callback-native.test.js`
   and `test/issue-66-cfapi-positive-shape-native.test.js` still call
   `spawnSync(executable)` on TEMP-built EXEs. The receipt helper also
   launches a path after its hash and file-identity check. A swap before
   `CreateProcess`, mutable `compile.cmd` / `build.cmd`, a substituted
   compiler or vcvars script, and DLL side-loading have no end-to-end
   independent custody proof. Never turn a SectionObjectPointer match
   alone into a claim of authenticated executed bytes.
2. **Native root / ACL:** parent directory handles alone did **not**
   prevent a real Windows ancestor rename; only the separately tested
   `NtCreateFile(RootDirectory=HANDLE)` primitive kept a child open bound
   to the original file object. That primitive is not integrated across
   creation, writes, cleanup, ACL admission, or the whole lifecycle.
   Hostile ancestor `FileSystemRights.Delete` remains a blocking risk;
   blindly rejecting it also broke legitimate fixture tests.
3. **Required-v2 recovery:** local `426d5e93f7b181aa8c055eb59b33f46c8f61cb3a`
   handles 16,385 legitimate trash entries in physical Windows/WSL
   crash tests, but independent adversarial review reproduced an ABA
   false acceptance through a pathname `fsp.opendir(trash)` and an
   independently replaced bind mount. Separate rooted NTFS/POSIX labs
   are not integrated into the protected snapshot, tracked-file SHA
   scan, marker promotion, journal or restart lifetime. Do not fast-forward
   `426d5e93` as a recovery fix.
4. **Formal and platform gates:** published #300 `956b2515` had
   CodeQL **FAILURE** with an uncontrolled absolute-path shell command
   annotation in the native ACL test; its Windows canonical/mandatory
   and Ubuntu full checks were green. No hosted CodeQL conclusion for
   these local candidates is asserted. Windows 10 physical CFAPI,
   independent root/owner issuance, NTFS physical power-cut durability
   and end-to-end external custody are not established.

**Decision:** preserve all RED fixtures, source candidates and native labs,
keep PR #300 OPEN/Draft, and do not push, merge, deploy, cut over or alter
`Root/main`. Require exact-SHA independent SOURCE GO, physical Windows
Node 22 NTFS and Ubuntu Node 22 ext4, authenticated byte and image custody,
formal CodeQL, and hosted checks for the same published SHA before any
different release decision.
